import os
import json
import re
import math
import hashlib
import zipfile
import string
from datetime import datetime
from urllib.parse import urlparse
import xml.etree.ElementTree as ET

from olefile import OleFileIO
from oletools.olevba import VBA_Parser, VBA_Scanner

# Optional: Ole10Native parser
try:
    from oletools import oleobj
except Exception:
    oleobj = None


# ================== CONFIG ==================
DATASET_ROOT = "/home/burak/Desktop/malicious_dataset"
DOCM_ROOT = os.path.join(DATASET_ROOT, "docm")

OUTPUT_ROOT = os.path.join(DATASET_ROOT, "malicious_docm_extraction_results")
os.makedirs(OUTPUT_ROOT, exist_ok=True)

MAX_TEXT_CHARS = 300_000
MAX_SNIPPET_CHARS = 10_000
MAX_SNIPPETS_PER_KIND = 40
MAX_BINARY_HEXDUMP_BYTES = 512
MAX_XML_FILES_TO_SCAN = 120  # limit for huge zips
# ============================================


# ================== JSON SAFE ==================
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
    return data[:max_bytes].hex()

def get_domain(url: str) -> str:
    try:
        p = urlparse(url)
        return (p.netloc or "").lower()
    except Exception:
        return ""


# ================== CODE SNIPPETS ==================
SCRIPT_KEYWORDS = [
    "python", "python.exe",
    "powershell", "powershell.exe",
    "cmd.exe", "cmd /c",
    "wscript", "cscript",
    "rundll32", "regsvr32",
    "mshta", "bitsadmin", "certutil",
]

def detect_code_snippets(text: str):
    snippets = {
        "javascript": [],
        "python": [],
        "powershell": [],
        "cmd_shell": [],
        "url_redirection": [],
        "download_exec": [],
    }

    # <script> blocks
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
    for line in text.splitlines():
        ll = line.lower()
        if any(k in ll for k in js_markers):
            snippets["javascript"].append(line.strip())
        if len(snippets["javascript"]) >= MAX_SNIPPETS_PER_KIND:
            break

    py_markers = ["import ", "from ", "def ", "class ", "subprocess", "os.system", "requests.", "urllib"]
    for line in text.splitlines():
        ll = line.lower()
        if any(ll.strip().startswith(k) for k in ["import ", "from ", "def ", "class "]):
            snippets["python"].append(line.strip())
        elif any(k in ll for k in py_markers):
            snippets["python"].append(line.strip())
        if len(snippets["python"]) >= MAX_SNIPPETS_PER_KIND:
            break

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

    redir_markers = ["location.href", "window.location", "document.location", "redirect", "http-equiv=\"refresh\""]
    for line in text.splitlines():
        ll = line.lower()
        if any(k in ll for k in redir_markers):
            snippets["url_redirection"].append(line.strip())
        if len(snippets["url_redirection"]) >= MAX_SNIPPETS_PER_KIND:
            break

    dl_markers = [
        "urldownloadtofile", "winhttp.winhttprequest", "msxml2.xmlhttp",
        "adodb.stream", "savetofile", "open(\"get\"", "downloadfile",
        "downloadstring", "invoke-webrequest",
    ]
    for line in text.splitlines():
        ll = line.lower()
        if any(k in ll for k in dl_markers):
            snippets["download_exec"].append(line.strip())
        if len(snippets["download_exec"]) >= MAX_SNIPPETS_PER_KIND:
            break

    for k in snippets:
        snippets[k] = list(dict.fromkeys([s for s in snippets[k] if s]))

    summary = {f"{k}_snippet_count": len(v) for k, v in snippets.items()}
    summary["total_code_snippet_count"] = sum(summary.values())
    return summary, snippets


# ================== FORMAT / LABEL ==================
def detect_file_format(file_path: str) -> str:
    try:
        with open(file_path, "rb") as f:
            header = f.read(8)
    except Exception:
        return "other"
    if header.startswith(b"PK\x03\x04") or header.startswith(b"PK\x05\x06") or header.startswith(b"PK\x07\x08"):
        return "zip_like"
    return "other"

def get_label_from_path(file_path: str) -> str:
    lower = file_path.lower()
    if os.sep + "malicious" + os.sep in lower:
        return "malicious"
    if os.sep + "benign" + os.sep in lower:
        return "benign"
    return "unknown"

def get_file_basic_info(file_path: str) -> dict:
    st = os.stat(file_path)
    fn = os.path.basename(file_path)
    _, ext = os.path.splitext(fn)
    return {
        "file_path": file_path,
        "file_name": fn,
        "file_ext": ext.lower(),
        "file_size_bytes": st.st_size,
        "sha256": sha256_file(file_path),
    }


# ================== FILE STATS ==================
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
    out["entropy_suspicious_flag"] = ent >= 7.2
    out["printable_ratio"] = float(printable_ratio_bytes(data))
    out["null_byte_ratio"] = float(null_byte_ratio(data))

    ext = os.path.splitext(file_path)[1].lower()
    fmt = detect_file_format(file_path)
    if ext == ".docm" and fmt != "zip_like":
        out["magic_mismatch"] = True
    return out


# ================== ZIP STRUCTURE ==================
def extract_zip_structure(file_path: str) -> dict:
    info = {
        "is_zip_valid": False,
        "zip_entry_count": 0,
        "zip_max_entry_size": 0,
        "zip_max_entry_entropy": 0.0,
        "zip_entry_names_sample": [],
        "has_content_types_xml": False,
        "content_type_macro_enabled_flag": False,
    }
    try:
        with zipfile.ZipFile(file_path, "r") as z:
            info["is_zip_valid"] = True
            names = z.namelist()
            info["zip_entry_count"] = len(names)
            info["has_content_types_xml"] = "[Content_Types].xml" in names
            info["zip_entry_names_sample"] = names[:200]

            max_size = 0
            max_ent = 0.0
            for name in names:
                try:
                    data = z.read(name)
                except Exception:
                    continue
                max_size = max(max_size, len(data))
                max_ent = max(max_ent, shannon_entropy(data))
            info["zip_max_entry_size"] = int(max_size)
            info["zip_max_entry_entropy"] = float(max_ent)

            # content types macro-enabled heuristic
            if "[Content_Types].xml" in names:
                try:
                    ct = z.read("[Content_Types].xml")
                    txt = safe_decode_latin1(ct).lower()
                    # docm macro content type often contains "macroenabled"
                    info["content_type_macro_enabled_flag"] = ("macroenabled" in txt) or ("vbaProject.bin".lower() in txt.lower())
                except Exception:
                    pass
    except Exception as e:
        info["error"] = f"zip_open_error: {e}"
    return info


# ================== RELATIONSHIPS ==================
def extract_relationships(file_path: str) -> dict:
    out = {
        "rels_total_count": 0,
        "rels_external_count": 0,
        "rels_external_url_count": 0,
        "rels_external_domain_bow": [],
        "has_remote_template_flag": False,
        "has_external_hyperlink_flag": False,
        "has_external_image_rel_flag": False,
        "has_oleobject_rel_flag": False,
        "has_package_rel_flag": False,
        "rels_external_urls": [],
        "rels_samples": [],  # limited
    }

    try:
        with zipfile.ZipFile(file_path, "r") as z:
            rels_files = [n for n in z.namelist() if n.endswith(".rels")]
            samples = []
            ext_urls = []
            ext_domains = set()

            for rf in rels_files:
                try:
                    data = z.read(rf)
                except Exception:
                    continue
                text = safe_decode_latin1(data)

                # parse XML safely
                try:
                    root = ET.fromstring(text)
                except Exception:
                    # fallback: regex external target
                    for m in re.finditer(r'TargetMode="External"[^>]*Target="([^"]+)"', text):
                        u = m.group(1)
                        ext_urls.append(u)
                        d = get_domain(u)
                        if d:
                            ext_domains.add(d)
                    continue

                # handle namespace-agnostic by checking tag endings
                for rel in root.iter():
                    if not rel.tag.lower().endswith("relationship"):
                        continue
                    out["rels_total_count"] += 1
                    target = rel.attrib.get("Target", "")
                    tmode = rel.attrib.get("TargetMode", "")
                    rtype = rel.attrib.get("Type", "")

                    is_external = (tmode.lower() == "external") or (target.lower().startswith(("http://", "https://")))
                    if is_external:
                        out["rels_external_count"] += 1
                        ext_urls.append(target)
                        d = get_domain(target)
                        if d:
                            ext_domains.add(d)

                    rtype_l = rtype.lower()
                    if "attachedtemplate" in rtype_l and is_external:
                        out["has_remote_template_flag"] = True
                    if rtype_l.endswith("/hyperlink") and is_external:
                        out["has_external_hyperlink_flag"] = True
                    if "/image" in rtype_l and is_external:
                        out["has_external_image_rel_flag"] = True
                    if "oleobject" in rtype_l:
                        out["has_oleobject_rel_flag"] = True
                    if "package" in rtype_l:
                        out["has_package_rel_flag"] = True

                    if len(samples) < 60:
                        samples.append({
                            "rels_file": rf,
                            "type": rtype,
                            "target": target,
                            "target_mode": tmode,
                            "external": bool(is_external),
                        })

            out["rels_external_urls"] = list(dict.fromkeys(ext_urls))[:500]
            out["rels_external_url_count"] = len(out["rels_external_urls"])
            out["rels_external_domain_bow"] = sorted(list(ext_domains))[:500]
            out["rels_samples"] = samples

    except Exception as e:
        out["error"] = f"rels_error: {e}"

    return out


# ================== METADATA (core/app) ==================
def _get_text_ns(root, localname: str):
    for el in root.iter():
        if el.tag.lower().endswith(localname.lower()):
            return (el.text or "").strip()
    return ""

def extract_docprops_metadata(file_path: str) -> dict:
    meta = {
        "core_creator_present": False,
        "core_lastmodifiedby_present": False,
        "core_created": None,
        "core_modified": None,
        "meta_time_anomaly_flag": False,

        "app_application_present": False,
        "app_template_present": False,

        "core_creator": "",
        "core_lastmodifiedby": "",
        "app_application": "",
        "app_template": "",
    }

    try:
        with zipfile.ZipFile(file_path, "r") as z:
            names = z.namelist()

            if "docProps/core.xml" in names:
                try:
                    core = safe_decode_latin1(z.read("docProps/core.xml"))
                    r = ET.fromstring(core)
                    creator = _get_text_ns(r, "creator")
                    lmb = _get_text_ns(r, "lastModifiedBy")
                    created = _get_text_ns(r, "created")
                    modified = _get_text_ns(r, "modified")

                    meta["core_creator"] = creator
                    meta["core_lastmodifiedby"] = lmb
                    meta["core_created"] = created or None
                    meta["core_modified"] = modified or None
                    meta["core_creator_present"] = bool(creator)
                    meta["core_lastmodifiedby_present"] = bool(lmb)

                    # simple anomaly: created exists and modified exists and created > modified lexicographically (ISO often comparable)
                    if created and modified and created > modified:
                        meta["meta_time_anomaly_flag"] = True
                except Exception:
                    pass

            if "docProps/app.xml" in names:
                try:
                    app = safe_decode_latin1(z.read("docProps/app.xml"))
                    r = ET.fromstring(app)
                    application = _get_text_ns(r, "Application")
                    template = _get_text_ns(r, "Template")

                    meta["app_application"] = application
                    meta["app_template"] = template
                    meta["app_application_present"] = bool(application)
                    meta["app_template_present"] = bool(template)
                except Exception:
                    pass

    except Exception as e:
        meta["error"] = f"docprops_error: {e}"

    return meta


# ================== VBA FROM vbaProject.bin ==================
def _empty_vba_summary():
    return {
        "has_macros": False,
        "macro_count": 0,
        "suspicious_keyword_count": 0,
        "autoexec_keyword_count": 0,
        "vba_length_chars": 0,
        "vba_line_count": 0,

        # keep useful extras
        "vba_digit_ratio": 0.0,
        "vba_non_printable_ratio": 0.0,

        "url_count": 0,
        "ip_like_count": 0,
        "shell_indicator_total_hits": 0,
        "script_keyword_total_hits": 0,
        "obfuscated_item_count": 0,

        # extra
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

def _empty_vba_strings():
    return {
        "all_vba_code": "",
        "macro_module_names": [],
        "urls": [],
        "ip_like_list": [],
        "suspicious_keywords_list": [],
        "autoexec_keywords_list": [],
        "string_literals": [],
        "shell_indicator_hits": {},
        "script_keyword_hits": {},
        "vba_obfuscation_items": [],
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

    code_len = len(full_code)
    summary["vba_length_chars"] = code_len
    summary["vba_line_count"] = full_code.count("\n") + 1 if code_len else 0

    digit_count = sum(ch.isdigit() for ch in full_code)
    non_printable_count = sum(ch not in string.printable for ch in full_code)
    summary["vba_digit_ratio"] = (digit_count / code_len) if code_len else 0.0
    summary["vba_non_printable_ratio"] = (non_printable_count / code_len) if code_len else 0.0

    urls = re.findall(r"https?://[^\s\"']+", full_code, flags=re.IGNORECASE)
    ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", full_code)
    strings_part["urls"] = urls
    strings_part["ip_like_list"] = ips
    summary["url_count"] = len(urls)
    summary["ip_like_count"] = len(ips)

    string_literals = re.findall(r'"([^"\r\n]{3,})"', full_code)
    strings_part["string_literals"] = string_literals

    shell_indicators = [
        "Shell", "WScript.Shell", "CreateObject", "cmd.exe", "powershell",
        "WinHttp.WinHttpRequest", "XMLHTTP", "Msxml2.XMLHTTP", "ADODB.Stream",
        "URLDownloadToFile",
    ]
    hits = {s: full_code.lower().count(s.lower()) for s in shell_indicators}
    strings_part["shell_indicator_hits"] = hits
    summary["shell_indicator_total_hits"] = sum(hits.values())

    # script keyword lines
    script_hits = {kw: [] for kw in SCRIPT_KEYWORDS}
    for line in full_code.splitlines():
        ll = line.lower()
        for kw in SCRIPT_KEYWORDS:
            if kw in ll:
                script_hits[kw].append(line.strip())
    script_hits = {k: v for k, v in script_hits.items() if v}
    strings_part["script_keyword_hits"] = script_hits
    summary["script_keyword_total_hits"] = sum(len(v) for v in script_hits.values())

    # obf counters
    low = full_code.lower()
    summary["vba_obf_chr_count"] = low.count("chr(") + low.count("chrw(")
    summary["vba_obf_strreverse_count"] = low.count("strreverse(")
    summary["vba_obf_replace_count"] = low.count("replace(")
    summary["vba_obf_split_join_count"] = low.count("split(") + low.count("join(")
    summary["vba_execute_eval_flag"] = any(k in low for k in ["execute", "eval(", "callbyname("])

    vba_b64 = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", full_code)
    vba_hex = re.findall(r"\b[0-9a-fA-F]{40,}\b", full_code)
    vba_b64 = list(dict.fromkeys(vba_b64))
    vba_hex = list(dict.fromkeys(vba_hex))
    strings_part["vba_base64_candidates"] = vba_b64
    strings_part["vba_hex_candidates"] = vba_hex
    summary["vba_base64_like_count"] = len(vba_b64)
    summary["vba_hex_like_count"] = len(vba_hex)

    high_ent = 0
    for s in string_literals:
        b = s.encode("latin-1", errors="ignore")
        if len(b) >= 40 and shannon_entropy(b) >= 4.2:
            high_ent += 1
    summary["vba_high_entropy_string_count"] = high_ent

    ps_cmd_markers = [
        "powershell", "cmd.exe", "cmd /c", "invoke-webrequest", "downloadstring",
        "new-object net.webclient", "frombase64string", "-enc", "encodedcommand",
    ]
    summary["vba_powershell_cmd_count"] = sum(low.count(m) for m in ps_cmd_markers)

    sn_sum, snips = detect_code_snippets(full_code)
    strings_part["vba_code_snippet_summary"] = sn_sum
    strings_part["vba_code_snippets"] = snips

    return summary, strings_part

def extract_vba_from_bytes(data: bytes, source_name: str):
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

        # oletools analyze_macros items
        obf_items = []
        obf_count = 0
        try:
            for kw_type, keyword, description in vba.analyze_macros():
                obf_items.append({"type": kw_type, "keyword": keyword, "description": description})
                t = (kw_type or "").lower()
                if any(x in t for x in ["hex string", "base64", "dridex", "obfus"]):
                    obf_count += 1
        except Exception as e:
            obf_items.append({"type": "error", "keyword": "", "description": f"analyze_macros_error: {e}"})

        strings_part["vba_obfuscation_items"] = obf_items
        summary["obfuscated_item_count"] = obf_count

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


# ================== EMBEDDED (word/embeddings) ==================
def _guess_payload_flags(data: bytes, filename: str):
    h = data[:16]
    name = (filename or "").lower()
    low = data.lower()

    is_pe = h.startswith(b"MZ") or name.endswith((".exe", ".dll", ".scr"))
    is_zip = h.startswith(b"PK\x03\x04") or name.endswith((".zip", ".docx", ".xlsx", ".pptx", ".xlsm", ".docm"))
    is_ole = h.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")

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
    if oleobj is not None:
        try:
            ns = oleobj.OleNativeStream(stream_data)
            fname = getattr(ns, "filename", None)
            payload = getattr(ns, "data", b"") or b""
            return fname, payload, None
        except Exception as e:
            return None, b"", f"oleobj_parse_error: {e}"
    return None, stream_data, "oleobj_not_available_fallback_raw"

def extract_ole10native_from_ole_bytes(ole_bytes: bytes, source_name: str):
    out = {
        "ole10native_object_count": 0,
        "objects": [],
    }
    try:
        ole = OleFileIO(ole_bytes)
    except Exception as e:
        out["error"] = f"nested_ole_open_error: {e}"
        return out

    try:
        streams = ole.listdir(streams=True, storages=False)
        for p in streams:
            sp = "/".join(p)
            if "ole10native" not in sp.lower():
                continue
            try:
                raw = ole.openstream(p).read()
            except Exception:
                continue
            fname, payload, perr = _parse_ole10native_best_effort(raw)
            payload = payload or b""
            text = safe_decode_latin1(payload)

            urls = re.findall(r"https?://[^\s\"']+", text, flags=re.IGNORECASE)
            cs_sum, cs = detect_code_snippets(text)

            obj = {
                "stream_path": sp,
                "parse_error": perr,
                "embedded_filename": fname,
                "payload_size_bytes": len(payload),
                "payload_sha256": sha256_bytes(payload) if payload else "",
                "payload_entropy": float(shannon_entropy(payload)),
                "urls": urls,
                "code_snippet_summary": cs_sum,
                "code_snippets": cs,
                "is_textish": bool(printable_ratio_bytes(payload) >= 0.70 and null_byte_ratio(payload) < 0.10),
            }
            if obj["is_textish"]:
                t = text
                if len(t) > MAX_TEXT_CHARS:
                    t = t[:MAX_TEXT_CHARS] + "\n...[TRUNCATED]..."
                obj["payload_text"] = t
            else:
                obj["binary_hexdump_preview"] = hexdump_preview(payload)

            out["objects"].append(obj)
            out["ole10native_object_count"] += 1

    except Exception as e:
        out["error"] = f"nested_ole_parse_error: {e}"
    finally:
        try:
            ole.close()
        except Exception:
            pass

    return out

def extract_embeddings(file_path: str) -> dict:
    out = {
        "embedded_part_count": 0,
        "embedded_ext_bow": [],
        "embedded_max_size": 0,
        "embedded_max_entropy": 0.0,
        "embedded_executable_like_count": 0,
        "embedded_zip_like_count": 0,
        "embedded_ole2_like_count": 0,
        "embedded_script_like_count": 0,
        "embedded_parts": [],
    }

    try:
        with zipfile.ZipFile(file_path, "r") as z:
            names = z.namelist()
            emb = [n for n in names if n.lower().startswith("word/embeddings/")]

            out["embedded_part_count"] = len(emb)
            for name in emb:
                try:
                    data = z.read(name)
                except Exception:
                    continue

                ent = shannon_entropy(data)
                out["embedded_max_size"] = max(out["embedded_max_size"], len(data))
                out["embedded_max_entropy"] = max(out["embedded_max_entropy"], ent)

                ext = ""
                if "." in name:
                    ext = "." + name.split(".")[-1].lower()
                    out["embedded_ext_bow"].append(ext)

                flags = _guess_payload_flags(data, name)
                if flags["is_pe_executable_like"]:
                    out["embedded_executable_like_count"] += 1
                if flags["is_zip_like"]:
                    out["embedded_zip_like_count"] += 1
                if flags["is_ole2_like"]:
                    out["embedded_ole2_like_count"] += 1
                if flags["is_javascript_like"] or flags["is_powershell_like"] or flags["is_vbs_like"] or flags["is_python_like"]:
                    out["embedded_script_like_count"] += 1

                text = safe_decode_latin1(data)
                urls = re.findall(r"https?://[^\s\"']+", text, flags=re.IGNORECASE)
                cs_sum, cs = detect_code_snippets(text)

                part = {
                    "part_name": name,
                    "size_bytes": len(data),
                    "sha256": sha256_bytes(data),
                    "entropy": float(ent),
                    "flags": flags,
                    "urls": urls,
                    "code_snippet_summary": cs_sum,
                    "code_snippets": cs,
                    "is_textish": bool(printable_ratio_bytes(data) >= 0.70 and null_byte_ratio(data) < 0.10),
                }

                # if OLE2, try nested Ole10Native extraction + nested VBA
                if flags["is_ole2_like"]:
                    part["nested_ole10native"] = extract_ole10native_from_ole_bytes(data, source_name=name)
                    vba_sum, vba_str = extract_vba_from_bytes(data, source_name=name)
                    part["nested_vba_summary"] = vba_sum
                    part["nested_vba_strings"] = vba_str

                if part["is_textish"]:
                    t = text
                    if len(t) > MAX_TEXT_CHARS:
                        t = t[:MAX_TEXT_CHARS] + "\n...[TRUNCATED]..."
                    part["text_preview"] = t
                else:
                    part["binary_hexdump_preview"] = hexdump_preview(data)

                out["embedded_parts"].append(part)

            out["embedded_ext_bow"] = list(dict.fromkeys(out["embedded_ext_bow"]))

    except Exception as e:
        out["error"] = f"embeddings_error: {e}"

    return out


# ================== ActiveX ==================
def extract_activex(file_path: str) -> dict:
    out = {
        "activex_part_count": 0,
        "activex_suspicious_flag": False,
        "activex_parts": [],
    }
    try:
        with zipfile.ZipFile(file_path, "r") as z:
            ax = [n for n in z.namelist() if n.lower().startswith("word/activex/")]
            out["activex_part_count"] = len(ax)
            suspicious_hits = 0

            for name in ax[:300]:
                try:
                    data = z.read(name)
                except Exception:
                    continue
                text = safe_decode_latin1(data)
                cs_sum, cs = detect_code_snippets(text)
                if cs_sum.get("total_code_snippet_count", 0) > 0:
                    suspicious_hits += 1
                out["activex_parts"].append({
                    "part_name": name,
                    "size_bytes": len(data),
                    "entropy": float(shannon_entropy(data)),
                    "code_snippet_summary": cs_sum,
                    "code_snippets": cs,
                })

            out["activex_suspicious_flag"] = suspicious_hits > 0

    except Exception as e:
        out["error"] = f"activex_error: {e}"

    return out


# ================== customXml ==================
def extract_customxml(file_path: str) -> dict:
    out = {
        "customxml_part_count": 0,
        "customxml_suspicious_keyword_count": 0,
        "customxml_url_count": 0,
        "customxml_parts": [],
    }
    SUS_KWS = ["http://", "https://", "powershell", "cmd.exe", "mshta", "rundll32", "regsvr32", "wscript", "adodb.stream"]

    try:
        with zipfile.ZipFile(file_path, "r") as z:
            cxml = [n for n in z.namelist() if n.lower().startswith("customxml/")]
            out["customxml_part_count"] = len(cxml)

            for name in cxml[:200]:
                try:
                    data = z.read(name)
                except Exception:
                    continue
                text = safe_decode_latin1(data).lower()
                urls = re.findall(r"https?://[^\s\"']+", text)
                hits = sum(text.count(k) for k in SUS_KWS)
                out["customxml_url_count"] += len(urls)
                out["customxml_suspicious_keyword_count"] += hits

                cs_sum, cs = detect_code_snippets(safe_decode_latin1(data))

                out["customxml_parts"].append({
                    "part_name": name,
                    "size_bytes": len(data),
                    "urls": urls[:200],
                    "suspicious_keyword_hits": hits,
                    "code_snippet_summary": cs_sum,
                    "code_snippets": cs,
                })

    except Exception as e:
        out["error"] = f"customxml_error: {e}"

    return out


# ================== XML FIELD / DDE SCAN ==================
def extract_xml_indicators(file_path: str) -> dict:
    out = {
        "xml_instrtext_count": 0,
        "dde_field_flag": False,
        "field_cmd_suspicious_count": 0,
        "xml_external_url_count": 0,
        "xml_hyperlink_count": 0,
    }

    try:
        with zipfile.ZipFile(file_path, "r") as z:
            xmls = [n for n in z.namelist() if n.lower().startswith("word/") and n.lower().endswith(".xml")]
            xmls = xmls[:MAX_XML_FILES_TO_SCAN]

            total_text = ""
            for name in xmls:
                try:
                    data = z.read(name)
                except Exception:
                    continue
                t = safe_decode_latin1(data)
                total_text += "\n" + t

            low = total_text.lower()

            # crude counts
            out["xml_instrtext_count"] = low.count("w:instrtext")
            out["xml_hyperlink_count"] = low.count("w:hyperlink")

            urls = re.findall(r"https?://[^\s\"']+", total_text, flags=re.IGNORECASE)
            out["xml_external_url_count"] = len(urls)

            # DDE markers
            dde_hits = low.count("ddeauto") + low.count(" dde ")
            out["dde_field_flag"] = dde_hits > 0

            # suspicious field commands
            cmd_markers = ["cmd.exe", "powershell", "mshta", "rundll32", "regsvr32", "wscript", "cscript"]
            out["field_cmd_suspicious_count"] = sum(low.count(m) for m in cmd_markers)

    except Exception as e:
        out["error"] = f"xml_scan_error: {e}"

    return out


# ================== RAW TEXT SCAN (whole file bytes) ==================
def extract_raw_text_features(file_path: str):
    summary = {
        "raw_size_bytes": 0,
        "url_count": 0,
        "ip_like_count": 0,
        "script_keyword_total_hits": 0,
        "base64_candidate_count": 0,
        "hex_candidate_count": 0,
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
    ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)
    strings["urls"] = urls
    strings["ip_like_list"] = ips
    summary["url_count"] = len(urls)
    summary["ip_like_count"] = len(ips)

    script_hits = {kw: [] for kw in SCRIPT_KEYWORDS}
    for line in text.splitlines():
        ll = line.lower()
        for kw in SCRIPT_KEYWORDS:
            if kw in ll:
                script_hits[kw].append(line.strip())
    script_hits = {k: v for k, v in script_hits.items() if v}
    strings["script_keyword_hits"] = script_hits
    summary["script_keyword_total_hits"] = sum(len(v) for v in script_hits.values())

    b64 = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", text)
    hx = re.findall(r"\b[0-9a-fA-F]{40,}\b", text)
    b64 = list(dict.fromkeys(b64))
    hx = list(dict.fromkeys(hx))
    strings["base64_candidates"] = b64
    strings["hex_candidates"] = hx
    summary["base64_candidate_count"] = len(b64)
    summary["hex_candidate_count"] = len(hx)

    SUS = ["mshta", "rundll32", "regsvr32", "certutil", "bitsadmin",
           "invoke-webrequest", "downloadstring", "new-object net.webclient",
           "wscript.shell", "createobject", "adodb.stream", "urldownloadtofile",
           "location.href", "window.location", "document.location",
           "frombase64string", "encodedcommand", "-enc"]
    sus_hits = {k: [] for k in SUS}
    for line in text.splitlines():
        ll = line.lower()
        for k in SUS:
            if k in ll:
                sus_hits[k].append(line.strip())
    sus_hits = {k: v for k, v in sus_hits.items() if v}
    strings["suspicious_keyword_hits"] = sus_hits
    summary["carved_suspicious_keyword_count"] = sum(len(v) for v in sus_hits.values())

    cs_sum, cs = detect_code_snippets(text)
    strings["code_snippet_summary"] = cs_sum
    strings["code_snippets"] = cs
    summary["code_snippet_total_count"] = cs_sum.get("total_code_snippet_count", 0)

    return summary, strings


# ================== DOCM MAIN EXTRACTION ==================
def extract_docm(file_path: str) -> dict:
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

    zip_struct = extract_zip_structure(file_path)
    if "error" in zip_struct:
        errors.append(zip_struct["error"])

    rels = extract_relationships(file_path)
    if "error" in rels:
        errors.append(rels["error"])

    meta = extract_docprops_metadata(file_path)
    if "error" in meta:
        errors.append(meta["error"])

    xml_ind = extract_xml_indicators(file_path)
    if "error" in xml_ind:
        errors.append(xml_ind["error"])

    vba_project = {
        "has_vba_project_bin": False,
        "vba_project_size": 0,
        "vba_project_entropy": 0.0,
        "vba_summary": _empty_vba_summary(),
        "vba_strings": _empty_vba_strings(),
    }

    embeddings = {}
    activex = {}
    customxml = {}

    # Read macro + other parts from ZIP
    if file_format == "zip_like":
        try:
            with zipfile.ZipFile(file_path, "r") as z:
                names = z.namelist()

                # VBA
                if "word/vbaProject.bin" in names:
                    vba_project["has_vba_project_bin"] = True
                    vb = z.read("word/vbaProject.bin")
                    vba_project["vba_project_size"] = len(vb)
                    vba_project["vba_project_entropy"] = float(shannon_entropy(vb))
                    vsum, vstr = extract_vba_from_bytes(vb, source_name="word/vbaProject.bin")
                    vba_project["vba_summary"] = vsum
                    vba_project["vba_strings"] = vstr

                # embeddings / activex / customxml
                embeddings = extract_embeddings(file_path)
                activex = extract_activex(file_path)
                customxml = extract_customxml(file_path)

                for sec in (embeddings, activex, customxml):
                    if isinstance(sec, dict) and "error" in sec:
                        errors.append(sec["error"])

        except Exception as e:
            errors.append(f"zip_read_error: {e}")

    # ---------- FLAT FEATURES (ML-friendly keywords) ----------
    features = {
        # file
        "file_size_bytes": file_info.get("file_size_bytes", 0),
        "sha256": file_info.get("sha256", ""),
        "magic_mismatch": file_stats.get("magic_mismatch", False),
        "parse_errors_count": len(errors),

        # stats
        "file_entropy": file_stats.get("file_entropy", 0.0),
        "entropy_suspicious_flag": file_stats.get("entropy_suspicious_flag", False),
        "printable_ratio": file_stats.get("printable_ratio", 0.0),
        "null_byte_ratio": file_stats.get("null_byte_ratio", 0.0),

        # zip
        "is_zip_valid": zip_struct.get("is_zip_valid", False),
        "zip_entry_count": zip_struct.get("zip_entry_count", 0),
        "zip_max_entry_size": zip_struct.get("zip_max_entry_size", 0),
        "zip_max_entry_entropy": zip_struct.get("zip_max_entry_entropy", 0.0),
        "has_content_types_xml": zip_struct.get("has_content_types_xml", False),
        "content_type_macro_enabled_flag": zip_struct.get("content_type_macro_enabled_flag", False),

        # rels
        "rels_total_count": rels.get("rels_total_count", 0),
        "rels_external_count": rels.get("rels_external_count", 0),
        "rels_external_url_count": rels.get("rels_external_url_count", 0),
        "has_remote_template_flag": rels.get("has_remote_template_flag", False),
        "has_external_hyperlink_flag": rels.get("has_external_hyperlink_flag", False),
        "has_external_image_rel_flag": rels.get("has_external_image_rel_flag", False),
        "has_oleobject_rel_flag": rels.get("has_oleobject_rel_flag", False),
        "has_package_rel_flag": rels.get("has_package_rel_flag", False),

        # metadata
        "core_creator_present": meta.get("core_creator_present", False),
        "core_lastmodifiedby_present": meta.get("core_lastmodifiedby_present", False),
        "meta_time_anomaly_flag": meta.get("meta_time_anomaly_flag", False),
        "app_application_present": meta.get("app_application_present", False),
        "app_template_present": meta.get("app_template_present", False),

        # xml indicators
        "xml_instrtext_count": xml_ind.get("xml_instrtext_count", 0),
        "dde_field_flag": xml_ind.get("dde_field_flag", False),
        "field_cmd_suspicious_count": xml_ind.get("field_cmd_suspicious_count", 0),
        "xml_external_url_count": xml_ind.get("xml_external_url_count", 0),
        "xml_hyperlink_count": xml_ind.get("xml_hyperlink_count", 0),

        # macro
        "has_vba_project_bin": vba_project.get("has_vba_project_bin", False),
        "vba_project_size": vba_project.get("vba_project_size", 0),
        "vba_project_entropy": vba_project.get("vba_project_entropy", 0.0),
        "has_vba": vba_project.get("vba_summary", {}).get("has_macros", False),
        "vba_module_count": len(set(vba_project.get("vba_strings", {}).get("macro_module_names", []) or [])),
        "vba_line_count": vba_project.get("vba_summary", {}).get("vba_line_count", 0),
        "vba_autoexec_count": vba_project.get("vba_summary", {}).get("autoexec_keyword_count", 0),
        "vba_suspicious_api_count": vba_project.get("vba_summary", {}).get("suspicious_keyword_count", 0),
        "vba_powershell_cmd_count": vba_project.get("vba_summary", {}).get("vba_powershell_cmd_count", 0),
        "vba_url_count": vba_project.get("vba_summary", {}).get("url_count", 0),
        "vba_base64_like_count": vba_project.get("vba_summary", {}).get("vba_base64_like_count", 0),
        "vba_hex_like_count": vba_project.get("vba_summary", {}).get("vba_hex_like_count", 0),
        "vba_high_entropy_string_count": vba_project.get("vba_summary", {}).get("vba_high_entropy_string_count", 0),
        "vba_obf_chr_count": vba_project.get("vba_summary", {}).get("vba_obf_chr_count", 0),
        "vba_obf_strreverse_count": vba_project.get("vba_summary", {}).get("vba_obf_strreverse_count", 0),
        "vba_obf_replace_count": vba_project.get("vba_summary", {}).get("vba_obf_replace_count", 0),
        "vba_obf_split_join_count": vba_project.get("vba_summary", {}).get("vba_obf_split_join_count", 0),
        "vba_execute_eval_flag": vba_project.get("vba_summary", {}).get("vba_execute_eval_flag", False),

        # embeddings
        "embedded_part_count": embeddings.get("embedded_part_count", 0) if isinstance(embeddings, dict) else 0,
        "embedded_max_size": embeddings.get("embedded_max_size", 0) if isinstance(embeddings, dict) else 0,
        "embedded_max_entropy": embeddings.get("embedded_max_entropy", 0.0) if isinstance(embeddings, dict) else 0.0,
        "embedded_executable_like_count": embeddings.get("embedded_executable_like_count", 0) if isinstance(embeddings, dict) else 0,
        "embedded_zip_like_count": embeddings.get("embedded_zip_like_count", 0) if isinstance(embeddings, dict) else 0,
        "embedded_ole2_like_count": embeddings.get("embedded_ole2_like_count", 0) if isinstance(embeddings, dict) else 0,
        "embedded_script_like_count": embeddings.get("embedded_script_like_count", 0) if isinstance(embeddings, dict) else 0,

        # activex
        "activex_part_count": activex.get("activex_part_count", 0) if isinstance(activex, dict) else 0,
        "activex_suspicious_flag": activex.get("activex_suspicious_flag", False) if isinstance(activex, dict) else False,

        # customxml
        "customxml_part_count": customxml.get("customxml_part_count", 0) if isinstance(customxml, dict) else 0,
        "customxml_suspicious_keyword_count": customxml.get("customxml_suspicious_keyword_count", 0) if isinstance(customxml, dict) else 0,
        "customxml_url_count": customxml.get("customxml_url_count", 0) if isinstance(customxml, dict) else 0,

        # raw IOC/snippets (whole file)
        "carved_url_count": raw_summary.get("url_count", 0),
        "carved_ip_count": raw_summary.get("ip_like_count", 0),
        "carved_suspicious_keyword_count": raw_summary.get("carved_suspicious_keyword_count", 0),
        "raw_code_snippet_total_count": raw_summary.get("code_snippet_total_count", 0),
    }

    record = {
        "label": label,
        "file_info": file_info,
        "file_format": file_format,

        "features": features,
        "file_stats": file_stats,
        "zip_structure": zip_struct,
        "relationships": rels,
        "docprops": meta,
        "xml_indicators": xml_ind,

        # macro + deep visibility
        "vba_project": vba_project,

        # embedded & extras
        "embeddings": embeddings,
        "activex": activex,
        "customxml": customxml,

        "raw_text_summary": raw_summary,
        "raw_text_strings": raw_strings,

        "errors": errors,
    }

    return make_json_safe(record)


# ================== FILE ITERATION ==================
def iter_docm_files():
    for label_dir in ["malicious", "benign"]:
        base_dir = os.path.join(DOCM_ROOT, label_dir)
        if not os.path.isdir(base_dir):
            print(f"[WARN] Folder not found: {base_dir}")
            continue
        for root, dirs, files in os.walk(base_dir):
            for fname in files:
                if fname.lower().endswith(".docm"):
                    yield os.path.join(root, fname)


def main():
    print(f"[*] DOCM extraction started at {datetime.now()}")
    count = 0
    for fp in iter_docm_files():
        rec = extract_docm(fp)
        out_path = os.path.join(OUTPUT_ROOT, os.path.basename(fp) + ".json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(rec, f, ensure_ascii=False, indent=2)
        print(f"[OK] {fp} -> {out_path}")
        count += 1
    print(f"[*] Finished at {datetime.now()}, total files processed: {count}")

if __name__ == "__main__":
    main()
