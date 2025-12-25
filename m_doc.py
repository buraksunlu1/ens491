import os
import json
import re
import string
import math
import hashlib
from datetime import datetime

from olefile import OleFileIO
from oletools.olevba import VBA_Parser, VBA_Scanner
from oletools import rtfobj

# Optional: Ole10Native parser (best effort)
try:
    from oletools import oleobj
except Exception:
    oleobj = None


# ================== CONFIG ==================
DATASET_ROOT = "/home/burak/Desktop/malicious_dataset"
DOC_ROOT = os.path.join(DATASET_ROOT, "doc")

OUTPUT_ROOT = os.path.join(DATASET_ROOT, "malicious_doc_extraction_results")
os.makedirs(OUTPUT_ROOT, exist_ok=True)

# Prevent JSON from exploding while still being useful for LLM training
MAX_EMBEDDED_TEXT_CHARS = 300_000
MAX_SNIPPET_CHARS = 10_000
MAX_SNIPPETS_PER_KIND = 40
MAX_STREAM_TEXT_PREVIEW = 120_000
MAX_BINARY_HEXDUMP_BYTES = 512  # only preview for binaries
# ============================================


# ================== JSON SAFETY ==================

def make_json_safe(obj):
    if isinstance(obj, dict):
        return {k: make_json_safe(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [make_json_safe(v) for v in obj]
    elif isinstance(obj, (bytes, bytearray)):
        try:
            return obj.decode("utf-8", errors="ignore")
        except Exception:
            return obj.hex()
    else:
        return obj


# ================== BASIC HELPERS ==================

def sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()

def sha256_file(file_path: str) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ent = 0.0
    n = len(data)
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return float(ent)

def printable_ratio_bytes(data: bytes) -> float:
    if not data:
        return 0.0
    printable = 0
    for b in data:
        if 32 <= b <= 126 or b in (9, 10, 13):
            printable += 1
    return printable / len(data)

def null_byte_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return data.count(b"\x00") / len(data)

def safe_decode_latin1(data: bytes) -> str:
    return data.decode("latin-1", errors="ignore")

def hexdump_preview(data: bytes, max_bytes: int = MAX_BINARY_HEXDUMP_BYTES) -> str:
    chunk = data[:max_bytes]
    return chunk.hex()


# ================== CODE SNIPPET EXTRACTION ==================

def detect_code_snippets(text: str):
    """
    Extract embedded JS/Python/PowerShell/CMD-like snippets.
    Returns:
      - summary counts
      - snippets dict: kind -> list[str]
    """
    snippets = {
        "javascript": [],
        "python": [],
        "powershell": [],
        "cmd_shell": [],
        "url_redirection": [],
        "download_exec": [],
    }

    # --- JS: <script> blocks ---
    for m in re.finditer(r"(?is)<script[^>]*>.*?</script>", text):
        block = m.group(0)
        if len(block) > MAX_SNIPPET_CHARS:
            block = block[:MAX_SNIPPET_CHARS] + "\n...[TRUNCATED]..."
        snippets["javascript"].append(block)
        if len(snippets["javascript"]) >= MAX_SNIPPETS_PER_KIND:
            break

    js_markers = [
        "eval(", "function(", "activexobject", "wscript",
        "document.location", "window.location", "location.href",
        "settimeout(", "fromcharcode", "atob(", "btoa(",
    ]
    if len(snippets["javascript"]) < MAX_SNIPPETS_PER_KIND:
        for line in text.splitlines():
            ll = line.lower()
            if any(k in ll for k in js_markers):
                snippets["javascript"].append(line.strip())
                if len(snippets["javascript"]) >= MAX_SNIPPETS_PER_KIND:
                    break

    # --- Python heuristic lines ---
    py_markers = ["import ", "from ", "def ", "class ", "subprocess", "os.system", "requests.", "urllib"]
    for line in text.splitlines():
        ll = line.lower()
        if any(ll.strip().startswith(k) for k in ["import ", "from ", "def ", "class "]):
            snippets["python"].append(line.strip())
        elif any(k in ll for k in py_markers):
            snippets["python"].append(line.strip())
        if len(snippets["python"]) >= MAX_SNIPPETS_PER_KIND:
            break

    # --- PowerShell heuristic lines ---
    ps_markers = [
        "powershell", "iex", "invoke-webrequest", "downloadstring",
        "new-object net.webclient", "start-process", "invoke-expression",
        "frombase64string", "-enc", "encodedcommand",
    ]
    for line in text.splitlines():
        ll = line.lower()
        if any(k in ll for k in ps_markers):
            snippets["powershell"].append(line.strip())
        if len(snippets["powershell"]) >= MAX_SNIPPETS_PER_KIND:
            break

    # --- CMD/Shell heuristic lines ---
    cmd_markers = [
        "cmd.exe", "cmd /c", "curl ", "wget ", "bitsadmin", "certutil",
        "mshta", "rundll32", "regsvr32", "powershell ",
    ]
    for line in text.splitlines():
        ll = line.lower()
        if any(k in ll for k in cmd_markers):
            snippets["cmd_shell"].append(line.strip())
        if len(snippets["cmd_shell"]) >= MAX_SNIPPETS_PER_KIND:
            break

    # --- URL redirection patterns ---
    redir_markers = ["location.href", "window.location", "document.location", "redirect", "http-equiv=\"refresh\""]
    for line in text.splitlines():
        ll = line.lower()
        if any(k in ll for k in redir_markers):
            snippets["url_redirection"].append(line.strip())
        if len(snippets["url_redirection"]) >= MAX_SNIPPETS_PER_KIND:
            break

    # --- Download/execute patterns (generic) ---
    dl_markers = [
        "urldownloadtofile", "winhttp.winhttprequest", "msxml2.xmlhttp",
        "adodb.stream", "saveToFile".lower(), "open(\"get\"".lower(),
        "downloadfile", "downloadstring", "invoke-webrequest",
    ]
    for line in text.splitlines():
        ll = line.lower()
        if any(k in ll for k in dl_markers):
            snippets["download_exec"].append(line.strip())
        if len(snippets["download_exec"]) >= MAX_SNIPPETS_PER_KIND:
            break

    # Deduplicate
    for k in snippets:
        snippets[k] = list(dict.fromkeys([s for s in snippets[k] if s]))

    summary = {f"{k}_snippet_count": len(v) for k, v in snippets.items()}
    summary["total_code_snippet_count"] = sum(summary.values())
    return summary, snippets


# ================== FILE FORMAT DETECTION ==================

def detect_file_format(file_path: str) -> str:
    """
    - classic OLE2 DOC  -> 'ole_doc'
    - RTF               -> 'rtf'
    - ZIP-like (PK..)   -> 'zip_like'
    - anything else     -> 'other'
    """
    try:
        with open(file_path, "rb") as f:
            header = f.read(16)
    except Exception:
        return "other"

    if header.startswith(b"{\\rtf"):
        return "rtf"

    if header.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"):
        return "ole_doc"

    if header.startswith(b"PK\x03\x04") or header.startswith(b"PK\x05\x06") or header.startswith(b"PK\x07\x08"):
        return "zip_like"

    return "other"


# ================== BASIC FILE INFO ==================

def get_file_basic_info(file_path: str) -> dict:
    st = os.stat(file_path)
    filename = os.path.basename(file_path)
    _, ext = os.path.splitext(filename)

    return {
        "file_path": file_path,
        "file_name": filename,
        "file_ext": ext.lower(),
        "file_size_bytes": st.st_size,
        "sha256": sha256_file(file_path),
    }

def get_label_from_path(file_path: str) -> str:
    lower = file_path.lower()
    if os.sep + "malicious" + os.sep in lower:
        return "malicious"
    if os.sep + "benign" + os.sep in lower:
        return "benign"
    return "unknown"


# ================== FILE STATISTICS ==================

def extract_file_stats(file_path: str) -> dict:
    out = {
        "file_entropy": 0.0,
        "entropy_suspicious_flag": False,
        "printable_ratio": 0.0,
        "null_byte_ratio": 0.0,
        "magic_mismatch": False,
    }
    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except Exception as e:
        out["error"] = f"stats_read_error: {e}"
        return out

    ent = shannon_entropy(data)
    out["file_entropy"] = float(ent)
    out["entropy_suspicious_flag"] = ent >= 7.2  # heuristic threshold
    out["printable_ratio"] = float(printable_ratio_bytes(data))
    out["null_byte_ratio"] = float(null_byte_ratio(data))

    ext = os.path.splitext(file_path)[1].lower()
    fmt = detect_file_format(file_path)
    if ext == ".doc" and fmt != "ole_doc":
        out["magic_mismatch"] = True
    if ext == ".rtf" and fmt != "rtf":
        out["magic_mismatch"] = True

    return out


# ================== OLE STRUCTURE FEATURES (NEW) ==================

def extract_ole_structure_features(file_path: str) -> dict:
    info = {
        "ole_is_valid": False,
        "ole_stream_count": 0,
        "ole_storage_count": 0,
        "ole_stream_names": [],
        "ole_stream_max_size": 0,
        "ole_stream_entropy_max": 0.0,

        "ole_has_worddocument": False,
        "ole_has_0table": False,
        "ole_has_1table": False,
        "ole_has_objectpool": False,
        "ole_has_ole10native": False,
        "ole_has_compobj": False,

        # best-effort signature/encryption heuristics
        "has_digital_signature": False,
        "signature_count": 0,
        "is_encrypted": False,
        "is_password_protected": False,
    }

    try:
        ole = OleFileIO(file_path)
    except Exception as e:
        info["error"] = f"ole_open_error: {e}"
        return info

    try:
        info["ole_is_valid"] = True

        stream_entries = ole.listdir(streams=True, storages=False)
        storage_entries = ole.listdir(streams=False, storages=True)

        info["ole_stream_count"] = len(stream_entries)
        info["ole_storage_count"] = len(storage_entries)

        stream_names = ["/".join(p) for p in stream_entries]
        info["ole_stream_names"] = stream_names
        lower_names = [n.lower() for n in stream_names]

        info["ole_has_worddocument"] = any(n.endswith("worddocument") for n in lower_names)
        info["ole_has_0table"] = any(n.endswith("0table") for n in lower_names)
        info["ole_has_1table"] = any(n.endswith("1table") for n in lower_names)
        info["ole_has_objectpool"] = any("objectpool" in n for n in lower_names)
        info["ole_has_ole10native"] = any("ole10native" in n for n in lower_names)
        info["ole_has_compobj"] = any(n.endswith("compobj") for n in lower_names)

        sig_hits = [n for n in lower_names if "digitalsignature" in n or "signature" in n]
        info["signature_count"] = len(sig_hits)
        info["has_digital_signature"] = info["signature_count"] > 0

        enc_hits = [n for n in lower_names if "encryptioninfo" in n or "encryptedpackage" in n]
        if enc_hits:
            info["is_encrypted"] = True
            info["is_password_protected"] = True

        max_size = 0
        max_ent = 0.0
        for p in stream_entries:
            try:
                data = ole.openstream(p).read()
                max_size = max(max_size, len(data))
                max_ent = max(max_ent, shannon_entropy(data))
            except Exception:
                continue

        info["ole_stream_max_size"] = max_size
        info["ole_stream_entropy_max"] = float(max_ent)

    except Exception as e:
        info["error"] = f"ole_structure_error: {e}"
    finally:
        try:
            ole.close()
        except Exception:
            pass

    return info


# ================== OLE METADATA (existing) ==================

def extract_ole_metadata(file_path: str) -> dict:
    meta_dict = {}
    try:
        ole = OleFileIO(file_path)
    except Exception as e:
        meta_dict["error"] = f"ole_open_error: {e}"
        return meta_dict

    try:
        meta = ole.get_metadata()
        meta_dict = {
            "author": meta.author,
            "last_saved_by": meta.last_saved_by,
            "title": meta.title,
            "subject": meta.subject,
            "comments": meta.comments,
            "template": meta.template,
            "revision_number": meta.revision_number,
            "create_time": str(meta.create_time) if meta.create_time else None,
            "last_saved_time": str(meta.last_saved_time) if meta.last_saved_time else None,
            "last_printed": str(meta.last_printed) if meta.last_printed else None,
            "num_pages": meta.num_pages,
            "num_words": meta.num_words,
            "num_chars": meta.num_chars,
            "application": meta.application,
        }
    except Exception as e:
        meta_dict = {"error": f"metadata_error: {e}"}
    finally:
        try:
            ole.close()
        except Exception:
            pass

    return meta_dict


# ================== VBA ANALYSIS (existing + new obf/snippets) ==================

SCRIPT_KEYWORDS = [
    "python", "python.exe",
    "powershell", "powershell.exe",
    "cmd.exe", "cmd /c",
    "wscript", "cscript",
    "bash", " sh ",
    "rundll32", "regsvr32",
    "mshta",
]

def _empty_vba_summary() -> dict:
    return {
        "has_macros": False,
        "macro_count": 0,
        "suspicious_keyword_count": 0,
        "autoexec_keyword_count": 0,
        "vba_length_chars": 0,
        "vba_line_count": 0,

        # KEEP (from your old code)
        "vba_digit_ratio": 0.0,
        "vba_non_printable_ratio": 0.0,

        "url_count": 0,
        "ip_like_count": 0,
        "shell_indicator_total_hits": 0,
        "script_keyword_total_hits": 0,
        "obfuscated_item_count": 0,

        # NEW explicit features
        "vba_obf_chr_count": 0,
        "vba_obf_strreverse_count": 0,
        "vba_obf_replace_count": 0,
        "vba_obf_split_join_count": 0,
        "vba_execute_eval_flag": False,
        "vba_base64_like_count": 0,
        "vba_hex_like_count": 0,
        "vba_high_entropy_string_count": 0,
        "vba_powershell_cmd_count": 0,
    }

def _empty_vba_strings() -> dict:
    return {
        "all_vba_code": "",
        "urls": [],
        "ip_like_list": [],
        "suspicious_keywords_list": [],
        "autoexec_keywords_list": [],

        # KEEP (from your old code)
        "string_literals": [],
        "shell_indicator_hits": {},
        "script_keyword_hits": {},
        "macro_module_names": [],
        "vba_obfuscation_items": [],

        # NEW
        "vba_base64_candidates": [],
        "vba_hex_candidates": [],
        "vba_code_snippet_summary": {},
        "vba_code_snippets": {},
    }

def _analyze_vba_code(full_code: str, module_names):
    summary = _empty_vba_summary()
    strings_part = _empty_vba_strings()
    strings_part["all_vba_code"] = full_code
    strings_part["macro_module_names"] = module_names

    # Suspicious / AutoExec keywords
    scanner = VBA_Scanner(full_code)
    suspicious_keywords = []
    autoexec_keywords = []

    for kw_type, keyword, description, pattern in scanner.scan():
        if kw_type == "Suspicious":
            suspicious_keywords.append(f"{keyword} - {description}")
        elif kw_type == "AutoExec":
            autoexec_keywords.append(f"{keyword} - {description}")

    summary["suspicious_keyword_count"] = len(suspicious_keywords)
    summary["autoexec_keyword_count"] = len(autoexec_keywords)
    strings_part["suspicious_keywords_list"] = suspicious_keywords
    strings_part["autoexec_keywords_list"] = autoexec_keywords

    # Size / structure
    code_len = len(full_code)
    summary["vba_length_chars"] = code_len
    summary["vba_line_count"] = full_code.count("\n") + 1 if code_len > 0 else 0

    digit_count = sum(ch.isdigit() for ch in full_code)
    non_printable_count = sum(ch not in string.printable for ch in full_code)
    summary["vba_digit_ratio"] = (digit_count / code_len) if code_len else 0.0
    summary["vba_non_printable_ratio"] = (non_printable_count / code_len) if code_len else 0.0

    # URLs & IPs
    urls = re.findall(r"https?://[^\s\"']+", full_code, flags=re.IGNORECASE)
    strings_part["urls"] = urls
    summary["url_count"] = len(urls)

    ip_like = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", full_code, flags=re.IGNORECASE)
    strings_part["ip_like_list"] = ip_like
    summary["ip_like_count"] = len(ip_like)

    # String literals (KEEP)
    string_literals = re.findall(r'"([^"\r\n]{3,})"', full_code)
    strings_part["string_literals"] = string_literals

    # Shell indicators (KEEP)
    shell_indicators = [
        "Shell",
        "WScript.Shell",
        "CreateObject",
        "cmd.exe",
        "powershell",
        "WinHttp.WinHttpRequest",
        "XMLHTTP",
        "Msxml2.XMLHTTP",
        "ADODB.Stream",
        "WScript.CreateObject",
        "WScript.Echo",
        "URLDownloadToFile",
    ]
    hits = {s: full_code.lower().count(s.lower()) for s in shell_indicators}
    strings_part["shell_indicator_hits"] = hits
    summary["shell_indicator_total_hits"] = sum(hits.values())

    # Script keyword lines (KEEP)
    script_hits = {kw: [] for kw in SCRIPT_KEYWORDS}
    for line in full_code.splitlines():
        lower_line = line.lower()
        for kw in SCRIPT_KEYWORDS:
            if kw in lower_line:
                script_hits[kw].append(line.strip())
    script_hits = {k: v for k, v in script_hits.items() if v}
    strings_part["script_keyword_hits"] = script_hits
    summary["script_keyword_total_hits"] = sum(len(v) for v in script_hits.values())

    # NEW: explicit obfuscation counters
    low = full_code.lower()
    summary["vba_obf_chr_count"] = low.count("chr(") + low.count("chrw(")
    summary["vba_obf_strreverse_count"] = low.count("strreverse(")
    summary["vba_obf_replace_count"] = low.count("replace(")
    summary["vba_obf_split_join_count"] = low.count("split(") + low.count("join(")
    summary["vba_execute_eval_flag"] = any(k in low for k in ["execute", "eval(", "callbyname("])

    # NEW: Base64/hex candidates inside VBA
    vba_b64 = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", full_code)
    vba_hex = re.findall(r"\b[0-9a-fA-F]{40,}\b", full_code)
    vba_b64 = list(dict.fromkeys(vba_b64))
    vba_hex = list(dict.fromkeys(vba_hex))
    strings_part["vba_base64_candidates"] = vba_b64
    strings_part["vba_hex_candidates"] = vba_hex
    summary["vba_base64_like_count"] = len(vba_b64)
    summary["vba_hex_like_count"] = len(vba_hex)

    # NEW: high-entropy string literals
    high_ent = 0
    for s in string_literals:
        b = s.encode("latin-1", errors="ignore")
        if len(b) >= 40 and shannon_entropy(b) >= 4.2:
            high_ent += 1
    summary["vba_high_entropy_string_count"] = high_ent

    # NEW: powershell/cmd count
    ps_cmd_markers = [
        "powershell", "cmd.exe", "cmd /c", "invoke-webrequest", "downloadstring",
        "new-object net.webclient", "frombase64string", "-enc", "encodedcommand",
    ]
    summary["vba_powershell_cmd_count"] = sum(low.count(m) for m in ps_cmd_markers)

    # NEW: code snippets inside VBA (sometimes embedded JS/PS)
    sn_sum, snips = detect_code_snippets(full_code)
    strings_part["vba_code_snippet_summary"] = sn_sum
    strings_part["vba_code_snippets"] = snips

    return summary, strings_part


def extract_vba_from_doc(file_path: str):
    base_summary = _empty_vba_summary()
    base_strings = _empty_vba_strings()

    try:
        vba = VBA_Parser(file_path)
    except Exception as e:
        base_summary["error"] = f"VBA_Parser_error: {e}"
        return base_summary, base_strings

    try:
        if not vba.detect_vba_macros():
            return base_summary, base_strings

        base_summary["has_macros"] = True

        all_code = []
        module_names = []

        for (subfilename, stream_path, vba_filename, vba_code) in vba.extract_macros():
            if vba_code:
                all_code.append(vba_code)
                module_names.append(vba_filename)
                base_summary["macro_count"] += 1

        full_code = "\n\n".join(all_code)
        summary, strings_part = _analyze_vba_code(full_code, module_names)

        # KEEP: oletools analyze_macros() output
        obf_items = []
        obf_count = 0
        try:
            for kw_type, keyword, description in vba.analyze_macros():
                item = {"type": kw_type, "keyword": keyword, "description": description}
                obf_items.append(item)
                t = (kw_type or "").lower()
                if any(x in t for x in ["hex string", "base64", "dridex", "obfus"]):
                    obf_count += 1
        except Exception as e:
            obf_items.append({"type": "error", "keyword": "", "description": f"analyze_macros_error: {e}"})

        strings_part["vba_obfuscation_items"] = obf_items
        summary["obfuscated_item_count"] = obf_count

        summary["has_macros"] = True
        summary["macro_count"] = base_summary["macro_count"]
        return summary, strings_part

    except Exception as e:
        base_summary["error"] = f"VBA_analysis_error: {e}"
        return base_summary, base_strings
    finally:
        try:
            vba.close()
        except Exception:
            pass


def extract_vba_from_ole_bytes(data: bytes, source_name: str):
    base_summary = _empty_vba_summary()
    base_strings = _empty_vba_strings()

    try:
        vba = VBA_Parser(filename=source_name, data=data)
    except Exception as e:
        base_summary["error"] = f"VBA_Parser_error: {e}"
        return base_summary, base_strings

    try:
        if not vba.detect_vba_macros():
            return base_summary, base_strings

        base_summary["has_macros"] = True

        all_code = []
        module_names = []

        for (subfilename, stream_path, vba_filename, vba_code) in vba.extract_macros():
            if vba_code:
                all_code.append(vba_code)
                module_names.append(vba_filename)
                base_summary["macro_count"] += 1

        full_code = "\n\n".join(all_code)
        summary, strings_part = _analyze_vba_code(full_code, module_names)

        obf_items = []
        obf_count = 0
        try:
            for kw_type, keyword, description in vba.analyze_macros():
                item = {"type": kw_type, "keyword": keyword, "description": description}
                obf_items.append(item)
                t = (kw_type or "").lower()
                if any(x in t for x in ["hex string", "base64", "dridex", "obfus"]):
                    obf_count += 1
        except Exception as e:
            obf_items.append({"type": "error", "keyword": "", "description": f"analyze_macros_error: {e}"})

        strings_part["vba_obfuscation_items"] = obf_items
        summary["obfuscated_item_count"] = obf_count

        summary["has_macros"] = True
        summary["macro_count"] = base_summary["macro_count"]
        return summary, strings_part

    except Exception as e:
        base_summary["error"] = f"VBA_analysis_error: {e}"
        return base_summary, base_strings
    finally:
        try:
            vba.close()
        except Exception:
            pass


# ================== NEW: OLE EMBEDDED OBJECT EXTRACTION ==================

def _guess_payload_flags(data: bytes, filename: str | None):
    header = data[:16]
    name = (filename or "").lower()

    is_pe = header.startswith(b"MZ") or name.endswith((".exe", ".dll", ".scr"))
    is_zip = header.startswith(b"PK\x03\x04") or name.endswith((".zip", ".docx", ".xlsx", ".pptx", ".xlsm", ".docm"))
    is_ole = header.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")

    low = data.lower()
    is_js = name.endswith(".js") or b"<script" in low or b"function(" in low or b"eval(" in low
    is_ps = name.endswith(".ps1") or b"powershell" in low or b"invoke-webrequest" in low or b"downloadstring" in low
    is_vbs = name.endswith(".vbs") or b"wscript" in low or b"cscript" in low
    is_py = name.endswith(".py") or b"import " in low or b"def " in low

    return {
        "is_pe_executable_like": bool(is_pe),
        "is_zip_like": bool(is_zip),
        "is_ole2_like": bool(is_ole),
        "is_javascript_like": bool(is_js),
        "is_powershell_like": bool(is_ps),
        "is_vbs_like": bool(is_vbs),
        "is_python_like": bool(is_py),
    }

def _parse_ole10native_best_effort(stream_data: bytes):
    """
    Best effort Ole10Native parsing.
    If oletools.oleobj exists: use OleNativeStream.
    Else fallback returns raw stream as payload.
    """
    if oleobj is not None:
        try:
            ns = oleobj.OleNativeStream(stream_data)
            fname = getattr(ns, "filename", None)
            payload = getattr(ns, "data", b"") or b""
            return fname, payload, None
        except Exception as e:
            return None, b"", f"oleobj_parse_error: {e}"

    return None, stream_data, "oleobj_not_available_fallback_raw"

def extract_ole_embedded_objects(file_path: str) -> dict:
    """
    Extract embedded payloads from OLE DOC by scanning streams for Ole10Native.
    Text payloads: store text + code snippets.
    Binary payloads: store hash/size/entropy + hexdump preview (no full dump).
    """
    out = {
        "embedded_object_count": 0,
        "embedded_executable_like_count": 0,
        "embedded_zip_like_count": 0,
        "embedded_ole2_like_count": 0,
        "embedded_script_like_count": 0,
        "embedded_file_ext_bow": [],
        "embedded_max_size": 0,
        "embedded_max_entropy": 0.0,
        "embedded_objects": [],
    }

    try:
        ole = OleFileIO(file_path)
    except Exception as e:
        out["error"] = f"ole_open_error: {e}"
        return out

    try:
        stream_entries = ole.listdir(streams=True, storages=False)

        for idx, p in enumerate(stream_entries):
            stream_name = "/".join(p)
            low_name = stream_name.lower()

            # Focus on Ole10Native carriers (most common for dropped files)
            if "ole10native" not in low_name:
                continue

            try:
                raw_stream = ole.openstream(p).read()
            except Exception as e:
                out["embedded_objects"].append({
                    "index": idx,
                    "stream_path": stream_name,
                    "error": f"stream_read_error: {e}"
                })
                continue

            filename, payload, parse_err = _parse_ole10native_best_effort(raw_stream)
            payload = payload or b""

            out["embedded_object_count"] += 1
            out["embedded_max_size"] = max(out["embedded_max_size"], len(payload))
            ent = shannon_entropy(payload)
            out["embedded_max_entropy"] = max(out["embedded_max_entropy"], ent)

            ext = ""
            if filename and "." in filename:
                ext = "." + filename.split(".")[-1].lower()
                out["embedded_file_ext_bow"].append(ext)

            flags = _guess_payload_flags(payload, filename)

            if flags["is_pe_executable_like"]:
                out["embedded_executable_like_count"] += 1
            if flags["is_zip_like"]:
                out["embedded_zip_like_count"] += 1
            if flags["is_ole2_like"]:
                out["embedded_ole2_like_count"] += 1
            if flags["is_javascript_like"] or flags["is_powershell_like"] or flags["is_vbs_like"] or flags["is_python_like"]:
                out["embedded_script_like_count"] += 1

            # Try treat as text (best effort) and extract code snippets
            text = safe_decode_latin1(payload)
            urls = re.findall(r"https?://[^\s\"']+", text, flags=re.IGNORECASE)
            ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text, flags=re.IGNORECASE)
            code_sum, code_snips = detect_code_snippets(text)

            is_textish = printable_ratio_bytes(payload) >= 0.70 and null_byte_ratio(payload) < 0.10

            obj = {
                "index": idx,
                "stream_path": stream_name,
                "ole10native_parse_error": parse_err,
                "embedded_filename": filename,
                "embedded_size_bytes": len(payload),
                "embedded_sha256": sha256_bytes(payload) if payload else "",
                "embedded_entropy": float(ent),
                "flags": flags,
                "urls": urls,
                "ip_like_list": ips,
                "code_snippet_summary": code_sum,
                "code_snippets": code_snips,
                "is_textish": bool(is_textish),
            }

            if is_textish:
                text_store = text
                truncated = False
                if len(text_store) > MAX_EMBEDDED_TEXT_CHARS:
                    text_store = text_store[:MAX_EMBEDDED_TEXT_CHARS] + "\n...[TRUNCATED]..."
                    truncated = True
                obj["extracted_text"] = text_store
                obj["text_truncated"] = truncated
            else:
                obj["binary_hexdump_preview"] = hexdump_preview(payload)
                obj["binary_preview_len"] = min(len(payload), MAX_BINARY_HEXDUMP_BYTES)

            out["embedded_objects"].append(obj)

        out["embedded_file_ext_bow"] = list(dict.fromkeys(out["embedded_file_ext_bow"]))

    except Exception as e:
        out["error"] = f"embedded_extract_error: {e}"
    finally:
        try:
            ole.close()
        except Exception:
            pass

    return out


# ================== NEW: STREAM-LEVEL SCANNING (EXTRA) ==================

def extract_suspicious_stream_texts(file_path: str) -> dict:
    """
    Scan *all* OLE streams for text-like content and suspicious keywords.
    This catches cases where payload/code is hidden in non-Ole10Native streams.
    Stores only previews to avoid huge JSON.
    """
    out = {
        "suspicious_stream_hit_count": 0,
        "streams": [],  # list of {stream_path, size, entropy, urls, snippets, preview}
    }

    keywords = [
        "powershell", "cmd.exe", "cmd /c", "mshta", "rundll32", "regsvr32",
        "wscript", "cscript", "invoke-webrequest", "downloadstring",
        "http://", "https://", "urlmon", "urldownloadtofile", "adodb.stream",
        "window.location", "document.location", "location.href",
    ]

    try:
        ole = OleFileIO(file_path)
    except Exception as e:
        out["error"] = f"ole_open_error: {e}"
        return out

    try:
        stream_entries = ole.listdir(streams=True, storages=False)

        for p in stream_entries:
            stream_path = "/".join(p)
            try:
                data = ole.openstream(p).read()
            except Exception:
                continue

            size = len(data)
            if size < 64:
                continue

            ent = shannon_entropy(data)
            pr = printable_ratio_bytes(data)
            nb = null_byte_ratio(data)

            # Only inspect text-ish streams, or high-risk names
            name_low = stream_path.lower()
            name_risky = any(k in name_low for k in ["macros", "vba", "__vba_project", "project", "dir", "objectpool"])
            textish = (pr >= 0.60 and nb < 0.15) or name_risky

            if not textish:
                continue

            text = safe_decode_latin1(data)
            low = text.lower()

            if not any(k in low for k in keywords):
                continue

            urls = re.findall(r"https?://[^\s\"']+", text, flags=re.IGNORECASE)
            cs_sum, cs = detect_code_snippets(text)

            preview = text
            truncated = False
            if len(preview) > MAX_STREAM_TEXT_PREVIEW:
                preview = preview[:MAX_STREAM_TEXT_PREVIEW] + "\n...[TRUNCATED]..."
                truncated = True

            out["streams"].append({
                "stream_path": stream_path,
                "size_bytes": size,
                "entropy": float(ent),
                "printable_ratio": float(pr),
                "null_byte_ratio": float(nb),
                "urls": urls,
                "code_snippet_summary": cs_sum,
                "code_snippets": cs,
                "text_preview": preview,
                "preview_truncated": truncated,
            })

        out["suspicious_stream_hit_count"] = len(out["streams"])

    except Exception as e:
        out["error"] = f"stream_scan_error: {e}"
    finally:
        try:
            ole.close()
        except Exception:
            pass

    return out


# ================== RTF ANALYSIS (existing + snippets) ==================

def extract_rtf_features(file_path: str) -> dict:
    info = {
        "rtf_object_count": 0,
        "embedded_ole_object_count": 0,
        "embedded_ole_with_macros_count": 0,
        "embedded_pe_like_count": 0,
        "embedded_zip_like_count": 0,
        "objects": [],
    }

    try:
        for index, orig_len, data in rtfobj.rtf_iter_objects(file_path):
            info["rtf_object_count"] += 1
            obj_entry = {
                "index": index,
                "orig_len": orig_len,
                "decoded_size": len(data),
            }

            header = data[:16]
            is_ole = header.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")
            is_pe = header.startswith(b"MZ")
            is_zip = header.startswith(b"PK\x03\x04")

            obj_entry["is_ole2"] = bool(is_ole)
            obj_entry["is_pe_executable_like"] = bool(is_pe)
            obj_entry["is_zip_like"] = bool(is_zip)

            if is_ole:
                info["embedded_ole_object_count"] += 1
            if is_pe:
                info["embedded_pe_like_count"] += 1
            if is_zip:
                info["embedded_zip_like_count"] += 1

            text_sample = safe_decode_latin1(data)
            urls = re.findall(r"https?://[^\s\"']+", text_sample, flags=re.IGNORECASE)
            if urls:
                obj_entry["urls"] = urls

            ip_like = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text_sample, flags=re.IGNORECASE)
            if ip_like:
                obj_entry["ip_like_list"] = ip_like

            cs_sum, cs = detect_code_snippets(text_sample)
            obj_entry["code_snippet_summary"] = cs_sum
            obj_entry["code_snippets"] = cs

            if is_ole:
                vba_summary, vba_strings = extract_vba_from_ole_bytes(data, source_name=f"rtf_object_{index}")
                obj_entry["vba_summary"] = vba_summary
                obj_entry["vba_strings"] = vba_strings
                if vba_summary.get("has_macros"):
                    info["embedded_ole_with_macros_count"] += 1

            info["objects"].append(obj_entry)

    except Exception as e:
        info["error"] = f"rtfobj_error: {e}"

    return info


# ================== RAW TEXT FEATURES (existing + more) ==================

def extract_raw_text_features(file_path: str):
    """
    Scan whole file as text to catch:
      - URLs / IPs
      - script keywords
      - base64/hex blobs
      - DDE fields
      - JS/Python/PS/CMD snippets
    """
    summary = {
        "raw_size_bytes": 0,
        "url_count": 0,
        "ip_like_count": 0,
        "script_keyword_total_hits": 0,
        "base64_candidate_count": 0,
        "hex_candidate_count": 0,

        "dde_field_flag": False,
        "dde_keyword_count": 0,
        "carved_suspicious_keyword_count": 0,
        "code_snippet_total_count": 0,
    }
    strings = {
        "urls": [],
        "ip_like_list": [],
        "script_keyword_hits": {},
        "base64_candidates": [],
        "hex_candidates": [],

        "suspicious_keyword_hits": {},
        "code_snippet_summary": {},
        "code_snippets": {},
        "dde_lines": [],
    }

    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except Exception as e:
        summary["error"] = f"raw_read_error: {e}"
        return summary, strings

    summary["raw_size_bytes"] = len(data)
    text = safe_decode_latin1(data)

    urls = re.findall(r"https?://[^\s\"']+", text, flags=re.IGNORECASE)
    ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text, flags=re.IGNORECASE)
    strings["urls"] = urls
    strings["ip_like_list"] = ips
    summary["url_count"] = len(urls)
    summary["ip_like_count"] = len(ips)

    # Script keyword lines (KEEP)
    script_hits = {kw: [] for kw in SCRIPT_KEYWORDS}
    for line in text.splitlines():
        ll = line.lower()
        for kw in SCRIPT_KEYWORDS:
            if kw in ll:
                script_hits[kw].append(line.strip())
    script_hits = {k: v for k, v in script_hits.items() if v}
    strings["script_keyword_hits"] = script_hits
    summary["script_keyword_total_hits"] = sum(len(v) for v in script_hits.values())

    # Base64 candidates (KEEP)
    base64_candidates = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", text)
    base64_candidates = list(dict.fromkeys(base64_candidates))
    strings["base64_candidates"] = base64_candidates
    summary["base64_candidate_count"] = len(base64_candidates)

    # Hex candidates (KEEP)
    hex_candidates = re.findall(r"\b[0-9a-fA-F]{40,}\b", text)
    hex_candidates = list(dict.fromkeys(hex_candidates))
    strings["hex_candidates"] = hex_candidates
    summary["hex_candidate_count"] = len(hex_candidates)

    # DDE fields (NEW)
    dde_lines = []
    for line in text.splitlines():
        ll = line.lower()
        if "ddeauto" in ll or re.search(r"\bdde\b", ll):
            dde_lines.append(line.strip())
            if len(dde_lines) >= 200:
                break
    strings["dde_lines"] = dde_lines
    summary["dde_keyword_count"] = len(dde_lines)
    summary["dde_field_flag"] = summary["dde_keyword_count"] > 0

    # More suspicious keywords (NEW)
    SUSPICIOUS_KWS = [
        "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin",
        "invoke-webrequest", "downloadstring", "new-object net.webclient",
        "wscript.shell", "createobject", "adodb.stream", "urldownloadtofile",
        "http-equiv=\"refresh\"", "location.href", "window.location", "document.location",
        "frombase64string", "encodedcommand", "-enc",
    ]
    sus_hits = {k: [] for k in SUSPICIOUS_KWS}
    for line in text.splitlines():
        ll = line.lower()
        for k in SUSPICIOUS_KWS:
            if k in ll:
                sus_hits[k].append(line.strip())
    sus_hits = {k: v for k, v in sus_hits.items() if v}
    strings["suspicious_keyword_hits"] = sus_hits
    summary["carved_suspicious_keyword_count"] = sum(len(v) for v in sus_hits.values())

    # Code snippets (NEW)
    cs_sum, cs = detect_code_snippets(text)
    strings["code_snippet_summary"] = cs_sum
    strings["code_snippets"] = cs
    summary["code_snippet_total_count"] = cs_sum.get("total_code_snippet_count", 0)

    return summary, strings


# ================== PROCESS SINGLE FILE ==================

def process_single_doc(file_path: str) -> dict:
    label = get_label_from_path(file_path)
    file_info = get_file_basic_info(file_path)
    file_format = detect_file_format(file_path)

    errors = []

    file_stats = extract_file_stats(file_path)
    if "error" in file_stats:
        errors.append(file_stats["error"])

    raw_summary, raw_strings = extract_raw_text_features(file_path)
    if "error" in raw_summary:
        errors.append(raw_summary["error"])

    ole_meta = {}
    ole_structure = {}
    embedded_ole = {}
    suspicious_streams = {}

    vba_summary = _empty_vba_summary()
    vba_strings = _empty_vba_strings()
    rtf_features = {}

    if file_format == "ole_doc":
        ole_structure = extract_ole_structure_features(file_path)
        if "error" in ole_structure:
            errors.append(ole_structure["error"])

        ole_meta = extract_ole_metadata(file_path)
        if "error" in ole_meta:
            errors.append(ole_meta["error"])

        embedded_ole = extract_ole_embedded_objects(file_path)
        if "error" in embedded_ole:
            errors.append(embedded_ole["error"])

        suspicious_streams = extract_suspicious_stream_texts(file_path)
        if "error" in suspicious_streams:
            errors.append(suspicious_streams["error"])

        vba_summary, vba_strings = extract_vba_from_doc(file_path)
        if "error" in vba_summary:
            errors.append(vba_summary["error"])

    elif file_format == "rtf":
        ole_meta = {"note": "RTF file – classic OLE metadata is not applicable."}
        rtf_features = extract_rtf_features(file_path)
        if "error" in rtf_features:
            errors.append(rtf_features["error"])

    elif file_format == "zip_like":
        ole_meta = {"note": "ZIP-like container (probably OOXML/DOCX). Use DOCX/DOCM extractor for deeper analysis."}
    else:
        ole_meta = {"note": "Unknown structure. Only raw-text features reliable."}

    # Flat ML-friendly features (keywords)
    features = {
        "file_size_bytes": file_info.get("file_size_bytes", 0),
        "sha256": file_info.get("sha256", ""),
        "magic_mismatch": file_stats.get("magic_mismatch", False),
        "parse_errors_count": len(errors),

        "is_encrypted": ole_structure.get("is_encrypted", False),
        "is_password_protected": ole_structure.get("is_password_protected", False),
        "has_digital_signature": ole_structure.get("has_digital_signature", False),
        "signature_count": ole_structure.get("signature_count", 0),

        "file_entropy": file_stats.get("file_entropy", 0.0),
        "entropy_suspicious_flag": file_stats.get("entropy_suspicious_flag", False),
        "printable_ratio": file_stats.get("printable_ratio", 0.0),
        "null_byte_ratio": file_stats.get("null_byte_ratio", 0.0),

        "ole_is_valid": ole_structure.get("ole_is_valid", False),
        "ole_stream_count": ole_structure.get("ole_stream_count", 0),
        "ole_storage_count": ole_structure.get("ole_storage_count", 0),
        "ole_stream_max_size": ole_structure.get("ole_stream_max_size", 0),
        "ole_stream_entropy_max": ole_structure.get("ole_stream_entropy_max", 0.0),
        "ole_has_worddocument": ole_structure.get("ole_has_worddocument", False),
        "ole_has_0table": ole_structure.get("ole_has_0table", False),
        "ole_has_1table": ole_structure.get("ole_has_1table", False),
        "ole_has_objectpool": ole_structure.get("ole_has_objectpool", False),
        "ole_has_ole10native": ole_structure.get("ole_has_ole10native", False),
        "ole_has_compobj": ole_structure.get("ole_has_compobj", False),

        "has_vba": vba_summary.get("has_macros", False),
        "vba_module_count": len(set(vba_strings.get("macro_module_names", []) or [])),
        "vba_line_count": vba_summary.get("vba_line_count", 0),
        "vba_autoexec_count": vba_summary.get("autoexec_keyword_count", 0),
        "vba_suspicious_api_count": vba_summary.get("suspicious_keyword_count", 0),
        "vba_powershell_cmd_count": vba_summary.get("vba_powershell_cmd_count", 0),
        "vba_url_count": vba_summary.get("url_count", 0),
        "vba_base64_like_count": vba_summary.get("vba_base64_like_count", 0),
        "vba_hex_like_count": vba_summary.get("vba_hex_like_count", 0),
        "vba_high_entropy_string_count": vba_summary.get("vba_high_entropy_string_count", 0),
        "vba_obf_chr_count": vba_summary.get("vba_obf_chr_count", 0),
        "vba_obf_strreverse_count": vba_summary.get("vba_obf_strreverse_count", 0),
        "vba_obf_replace_count": vba_summary.get("vba_obf_replace_count", 0),
        "vba_obf_split_join_count": vba_summary.get("vba_obf_split_join_count", 0),
        "vba_execute_eval_flag": vba_summary.get("vba_execute_eval_flag", False),

        "embedded_object_count": embedded_ole.get("embedded_object_count", 0),
        "embedded_executable_like_count": embedded_ole.get("embedded_executable_like_count", 0),
        "embedded_zip_like_count": embedded_ole.get("embedded_zip_like_count", 0),
        "embedded_ole2_like_count": embedded_ole.get("embedded_ole2_like_count", 0),
        "embedded_script_like_count": embedded_ole.get("embedded_script_like_count", 0),
        "embedded_max_size": embedded_ole.get("embedded_max_size", 0),
        "embedded_max_entropy": embedded_ole.get("embedded_max_entropy", 0.0),

        "dde_field_flag": raw_summary.get("dde_field_flag", False),
        "carved_url_count": raw_summary.get("url_count", 0),
        "carved_ip_count": raw_summary.get("ip_like_count", 0),
        "carved_suspicious_keyword_count": raw_summary.get("carved_suspicious_keyword_count", 0),
        "raw_code_snippet_total_count": raw_summary.get("code_snippet_total_count", 0),

        "suspicious_stream_hit_count": suspicious_streams.get("suspicious_stream_hit_count", 0),
    }

    record = {
        "label": label,
        "file_info": file_info,
        "file_format": file_format,

        "features": features,
        "file_stats": file_stats,

        "ole_structure": ole_structure,
        "ole_metadata": ole_meta,

        # NEW deep payload visibility
        "embedded_ole_objects": embedded_ole,
        "suspicious_stream_texts": suspicious_streams,

        "vba_summary": vba_summary,
        "vba_strings": vba_strings,

        "rtf_objects": rtf_features,

        "raw_text_summary": raw_summary,
        "raw_text_strings": raw_strings,

        "errors": errors,
    }

    safe_record = make_json_safe(record)
    base_name = os.path.basename(file_path)
    out_path = os.path.join(OUTPUT_ROOT, base_name + ".json")

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(safe_record, f, ensure_ascii=False, indent=2)

    print(f"[OK] {file_path} -> {out_path}")
    return safe_record


# ================== MAIN ==================

def iter_doc_files():
    """
    Yield .doc and .rtf files (exclude .docx) from:
        doc/malicious
        doc/benign
    """
    for label_dir in ["malicious", "benign"]:
        base_dir = os.path.join(DOC_ROOT, label_dir)
        if not os.path.isdir(base_dir):
            print(f"[WARN] Folder not found: {base_dir}")
            continue

        for root, dirs, files in os.walk(base_dir):
            for fname in files:
                name_lower = fname.lower()
                if name_lower.endswith(".docx"):
                    continue
                if name_lower.endswith(".doc") or name_lower.endswith(".rtf"):
                    yield os.path.join(root, fname)

def main():
    print(f"[*] DOC/RTF extraction started at {datetime.now()}")
    count = 0
    for file_path in iter_doc_files():
        process_single_doc(file_path)
        count += 1
    print(f"[*] Finished at {datetime.now()}, total files processed: {count}")

if __name__ == "__main__":
    main()
