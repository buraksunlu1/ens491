import os
import json
import re
import math
import hashlib
import zipfile
import string
from datetime import datetime
from typing import Tuple, List, Dict, Any
from urllib.parse import urlparse

import xml.etree.ElementTree as ET

from olefile import OleFileIO
from oletools.olevba import VBA_Parser, VBA_Scanner

# Optional: Ole10Native parser (oletools)
try:
    from oletools import oleobj
except Exception:
    oleobj = None


# ================== CONFIG ==================
DATASET_ROOT = "/home/burak/Desktop/malicious_dataset"
DOCX_ROOT = os.path.join(DATASET_ROOT, "docx")
OUTPUT_ROOT = os.path.join(DATASET_ROOT, "malicious_docx_extraction_results")
os.makedirs(OUTPUT_ROOT, exist_ok=True)

MAX_TEXT_CHARS = 250_000
MAX_SNIPPET_CHARS = 10_000
MAX_SNIPPETS_PER_KIND = 40
MAX_BINARY_HEXDUMP_BYTES = 512
MAX_XML_FILES_TO_SCAN = 160  # prevent huge packages from exploding
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
def sha256_file(file_path: str) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
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


# ================== FILE FORMAT DETECTION ==================
def detect_file_format(file_path: str) -> str:
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


# ================== BASIC FILE INFO & LABEL ==================
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


# ================== FILE STATS (WHOLE FILE) ==================
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
    if ext == ".docx" and fmt != "zip_like":
        out["magic_mismatch"] = True
    return out


# ================== DOCX METADATA (core + app) ==================
def _get_text_by_suffix(root, suffix: str):
    for el in root.iter():
        if el.tag.endswith(suffix) and el.text is not None:
            return el.text
    return None

def extract_docx_metadata(file_path: str) -> dict:
    meta = {}
    try:
        with zipfile.ZipFile(file_path, "r") as z:
            core_xml = None
            app_xml = None

            if "docProps/core.xml" in z.namelist():
                core_xml = z.read("docProps/core.xml")
            if "docProps/app.xml" in z.namelist():
                app_xml = z.read("docProps/app.xml")

            if core_xml:
                root = ET.fromstring(core_xml)
                meta["creator"] = _get_text_by_suffix(root, "creator")
                meta["last_modified_by"] = _get_text_by_suffix(root, "lastModifiedBy")
                meta["created"] = _get_text_by_suffix(root, "created")
                meta["modified"] = _get_text_by_suffix(root, "modified")
                meta["description"] = _get_text_by_suffix(root, "description")
                meta["subject"] = _get_text_by_suffix(root, "subject")
                meta["title"] = _get_text_by_suffix(root, "title")

            if app_xml:
                root = ET.fromstring(app_xml)
                pages = _get_text_by_suffix(root, "Pages")
                words = _get_text_by_suffix(root, "Words")
                chars = _get_text_by_suffix(root, "Characters")
                app_name = _get_text_by_suffix(root, "Application")
                template = _get_text_by_suffix(root, "Template")

                meta["num_pages"] = int(pages) if pages and pages.isdigit() else None
                meta["num_words"] = int(words) if words and words.isdigit() else None
                meta["num_chars"] = int(chars) if chars and chars.isdigit() else None
                meta["application"] = app_name
                meta["template"] = template

            # time anomaly heuristic
            created = meta.get("created")
            modified = meta.get("modified")
            meta["meta_time_anomaly_flag"] = bool(created and modified and created > modified)

    except Exception as e:
        meta = {"error": f"docx_metadata_error: {e}"}

    return meta


# ================== CODE / SNIPPET DETECTION ==================
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
        "msxml2.xmlhttp", "xmlhttp", "adodb.stream",
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

    redir_markers = [
        "location.href", "window.location", "document.location",
        "redirect", "http-equiv=\"refresh\"", "meta http-equiv=\"refresh\"",
    ]
    for line in text.splitlines():
        ll = line.lower()
        if any(k in ll for k in redir_markers):
            snippets["url_redirection"].append(line.strip())
        if len(snippets["url_redirection"]) >= MAX_SNIPPETS_PER_KIND:
            break

    dl_markers = [
        "urldownloadtofile", "winhttp.winhttprequest", "msxml2.xmlhttp",
        "adodb.stream", "savetofile", "open(\"get\"", "downloadfile",
        "downloadstring", "invoke-webrequest", "webclient",
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


# ================== VBA ANALYSIS HELPERS ==================
def _empty_vba_summary() -> dict:
    return {
        "has_macros": False,
        "macro_count": 0,
        "suspicious_keyword_count": 0,
        "autoexec_keyword_count": 0,
        "vba_length_chars": 0,
        "vba_line_count": 0,
        "vba_digit_ratio": 0.0,
        "vba_non_printable_ratio": 0.0,
        "url_count": 0,
        "ip_like_count": 0,
        "shell_indicator_total_hits": 0,
        "script_keyword_total_hits": 0,
        "obfuscated_item_count": 0,

        # extra useful counters
        "vba_base64_like_count": 0,
        "vba_hex_like_count": 0,
        "vba_high_entropy_string_count": 0,
        "vba_execute_eval_flag": False,
        "vba_obf_chr_count": 0,
        "vba_obf_strreverse_count": 0,
        "vba_obf_replace_count": 0,
        "vba_obf_split_join_count": 0,
        "vba_powershell_cmd_count": 0,
        "vba_code_snippet_total_count": 0,
    }

def _empty_vba_strings() -> dict:
    return {
        "all_vba_code": "",
        "urls": [],
        "ip_like_list": [],
        "suspicious_keywords_list": [],
        "autoexec_keywords_list": [],
        "string_literals": [],
        "shell_indicator_hits": {},
        "script_keyword_hits": {},
        "macro_module_names": [],
        "vba_obfuscation_items": [],

        # extra visibility
        "vba_base64_candidates": [],
        "vba_hex_candidates": [],
        "vba_code_snippet_summary": {},
        "vba_code_snippets": {},
    }

def _analyze_vba_code(full_code: str, module_names: List[str]) -> Tuple[dict, dict]:
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
    summary["vba_line_count"] = full_code.count("\n") + 1 if code_len > 0 else 0

    digit_count = sum(ch.isdigit() for ch in full_code)
    non_printable_count = sum(ch not in string.printable for ch in full_code)
    summary["vba_digit_ratio"] = (digit_count / code_len) if code_len else 0.0
    summary["vba_non_printable_ratio"] = (non_printable_count / code_len) if code_len else 0.0

    urls = re.findall(r"https?://[^\s\"']+", full_code, flags=re.IGNORECASE)
    strings_part["urls"] = urls
    summary["url_count"] = len(urls)

    ip_like = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", full_code)
    strings_part["ip_like_list"] = ip_like
    summary["ip_like_count"] = len(ip_like)

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

    script_hits: Dict[str, List[str]] = {kw: [] for kw in SCRIPT_KEYWORDS}
    for line in full_code.splitlines():
        ll = line.lower()
        for kw in SCRIPT_KEYWORDS:
            if kw in ll:
                script_hits[kw].append(line.strip())
    script_hits = {k: v for k, v in script_hits.items() if v}
    strings_part["script_keyword_hits"] = script_hits
    summary["script_keyword_total_hits"] = sum(len(v) for v in script_hits.values())

    # base64/hex candidates inside vba
    b64 = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", full_code)
    hx = re.findall(r"\b[0-9a-fA-F]{40,}\b", full_code)
    b64 = list(dict.fromkeys(b64))
    hx = list(dict.fromkeys(hx))
    strings_part["vba_base64_candidates"] = b64
    strings_part["vba_hex_candidates"] = hx
    summary["vba_base64_like_count"] = len(b64)
    summary["vba_hex_like_count"] = len(hx)

    # high entropy string literals
    high_ent = 0
    for s in string_literals:
        b = s.encode("latin-1", errors="ignore")
        if len(b) >= 40 and shannon_entropy(b) >= 4.2:
            high_ent += 1
    summary["vba_high_entropy_string_count"] = high_ent

    low = full_code.lower()
    summary["vba_execute_eval_flag"] = any(k in low for k in ["execute", "eval(", "callbyname("])
    summary["vba_obf_chr_count"] = low.count("chr(") + low.count("chrw(")
    summary["vba_obf_strreverse_count"] = low.count("strreverse(")
    summary["vba_obf_replace_count"] = low.count("replace(")
    summary["vba_obf_split_join_count"] = low.count("split(") + low.count("join(")

    ps_cmd_markers = [
        "powershell", "cmd.exe", "cmd /c", "invoke-webrequest", "downloadstring",
        "new-object net.webclient", "frombase64string", "-enc", "encodedcommand",
    ]
    summary["vba_powershell_cmd_count"] = sum(low.count(m) for m in ps_cmd_markers)

    sn_sum, snips = detect_code_snippets(full_code)
    strings_part["vba_code_snippet_summary"] = sn_sum
    strings_part["vba_code_snippets"] = snips
    summary["vba_code_snippet_total_count"] = sn_sum.get("total_code_snippet_count", 0)

    return summary, strings_part


def extract_vba_from_docx(file_path: str) -> Tuple[dict, dict]:
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
        all_code_chunks: List[str] = []
        module_names: List[str] = []

        for (subfilename, stream_path, vba_filename, vba_code) in vba.extract_macros():
            if vba_code:
                all_code_chunks.append(vba_code)
                module_names.append(vba_filename)
                base_summary["macro_count"] += 1

        full_code = "\n\n".join(all_code_chunks)
        summary, strings_part = _analyze_vba_code(full_code, module_names)

        # Obfuscation/encoded strings via analyze_macros()
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


def extract_vba_from_ole_bytes(data: bytes, source_name: str) -> Tuple[dict, dict]:
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
        all_code_chunks: List[str] = []
        module_names: List[str] = []

        for (subfilename, stream_path, vba_filename, vba_code) in vba.extract_macros():
            if vba_code:
                all_code_chunks.append(vba_code)
                module_names.append(vba_filename)
                base_summary["macro_count"] += 1

        full_code = "\n\n".join(all_code_chunks)
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


# ================== RELATIONSHIPS (EXTERNAL, REMOTE TEMPLATE, ETC.) ==================
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
        "rels_samples": [],
    }

    ext_urls = []
    ext_domains = set()
    samples = []

    try:
        with zipfile.ZipFile(file_path, "r") as z:
            rels_files = [n for n in z.namelist() if n.lower().endswith(".rels")]
            for rf in rels_files:
                try:
                    data = z.read(rf)
                except Exception:
                    continue
                text = safe_decode_latin1(data)

                try:
                    root = ET.fromstring(text)
                    for rel in root.iter():
                        if not rel.tag.lower().endswith("relationship"):
                            continue
                        out["rels_total_count"] += 1
                        target = rel.attrib.get("Target", "")
                        tmode = rel.attrib.get("TargetMode", "")
                        rtype = rel.attrib.get("Type", "")

                        is_external = (tmode.lower() == "external") or target.lower().startswith(("http://", "https://"))
                        if is_external:
                            out["rels_external_count"] += 1
                            ext_urls.append(target)
                            d = get_domain(target)
                            if d:
                                ext_domains.add(d)

                        rtype_l = (rtype or "").lower()
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

                except Exception:
                    # fallback regex external targets if xml parsing fails
                    for m in re.finditer(r'TargetMode="External"[^>]*Target="([^"]+)"', text):
                        u = m.group(1)
                        ext_urls.append(u)
                        d = get_domain(u)
                        if d:
                            ext_domains.add(d)

    except Exception as e:
        out["error"] = f"rels_error: {e}"

    out["rels_external_urls"] = list(dict.fromkeys(ext_urls))[:600]
    out["rels_external_url_count"] = len(out["rels_external_urls"])
    out["rels_external_domain_bow"] = sorted(list(ext_domains))[:600]
    out["rels_samples"] = samples
    return out


# ================== XML INDICATORS (DDE / FIELDS / INCLUDEPICTURE) ==================
def extract_xml_indicators(file_path: str) -> dict:
    out = {
        "xml_instrtext_count": 0,
        "dde_field_flag": False,
        "field_cmd_suspicious_count": 0,
        "xml_external_url_count": 0,
        "xml_hyperlink_count": 0,
        "include_picture_field_count": 0,
        "field_suspicious_lines": [],
    }

    cmd_markers = ["cmd.exe", "powershell", "mshta", "rundll32", "regsvr32", "wscript", "cscript", "certutil", "bitsadmin"]
    field_markers = ["w:instrtext", "ddeauto", " includePicture ".lower(), "includepicture", "ddefield"]

    try:
        with zipfile.ZipFile(file_path, "r") as z:
            xmls = [n for n in z.namelist() if n.lower().startswith("word/") and n.lower().endswith((".xml", ".vml"))]
            xmls = xmls[:MAX_XML_FILES_TO_SCAN]

            total = ""
            for name in xmls:
                try:
                    data = z.read(name)
                except Exception:
                    continue
                total += "\n" + safe_decode_latin1(data)

            low = total.lower()
            out["xml_instrtext_count"] = low.count("w:instrtext")
            out["xml_hyperlink_count"] = low.count("w:hyperlink")
            out["include_picture_field_count"] = low.count("includepicture")

            urls = re.findall(r"https?://[^\s\"']+", total, flags=re.IGNORECASE)
            out["xml_external_url_count"] = len(urls)

            dde_hits = low.count("ddeauto") + low.count(" dde ")
            out["dde_field_flag"] = dde_hits > 0

            out["field_cmd_suspicious_count"] = sum(low.count(m) for m in cmd_markers)

            # collect suspicious lines (limited)
            lines = total.splitlines()
            sus_lines = []
            for line in lines:
                ll = line.lower()
                if any(m in ll for m in field_markers) or any(m in ll for m in cmd_markers):
                    sus_lines.append(line.strip())
                if len(sus_lines) >= 120:
                    break
            out["field_suspicious_lines"] = sus_lines

    except Exception as e:
        out["error"] = f"xml_scan_error: {e}"

    return out


# ================== OLE10NATIVE FROM EMBEDDED OLE BYTES ==================
def _parse_ole10native_best_effort(stream_data: bytes):
    # Preferred: oletools.oleobj
    if oleobj is not None:
        try:
            ns = oleobj.OleNativeStream(stream_data)
            fname = getattr(ns, "filename", None)
            payload = getattr(ns, "data", b"") or b""
            return fname, payload, None
        except Exception as e:
            return None, b"", f"oleobj_parse_error: {e}"
    # fallback: return raw
    return None, stream_data, "oleobj_not_available_fallback_raw"

def extract_ole10native_from_ole_bytes(ole_bytes: bytes, source_name: str) -> dict:
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
            ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)
            b64 = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", text)
            hx = re.findall(r"\b[0-9a-fA-F]{40,}\b", text)
            b64 = list(dict.fromkeys(b64))
            hx = list(dict.fromkeys(hx))

            cs_sum, cs = detect_code_snippets(text)

            obj = {
                "source_name": source_name,
                "stream_path": sp,
                "parse_error": perr,
                "embedded_filename": fname,
                "payload_size_bytes": len(payload),
                "payload_sha256": sha256_bytes(payload) if payload else "",
                "payload_entropy": float(shannon_entropy(payload)),
                "payload_printable_ratio": float(printable_ratio_bytes(payload)),
                "payload_null_byte_ratio": float(null_byte_ratio(payload)),
                "urls": urls[:400],
                "ip_like_list": ips[:400],
                "base64_candidates": b64[:200],
                "hex_candidates": hx[:200],
                "code_snippet_summary": cs_sum,
                "code_snippets": cs,
            }

            is_textish = (obj["payload_printable_ratio"] >= 0.70 and obj["payload_null_byte_ratio"] < 0.10)
            obj["is_textish"] = bool(is_textish)
            if is_textish:
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


# ================== PACKAGE / EMBEDDED OBJECTS ==================
def _guess_payload_flags(data: bytes, name: str) -> dict:
    h = data[:16]
    low = data.lower()
    n = (name or "").lower()

    is_ole = h.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")
    is_pe = h.startswith(b"MZ")
    is_zip = h.startswith(b"PK\x03\x04")
    is_rtf = h.startswith(b"{\\rtf")
    is_pdf = h.startswith(b"%PDF")

    is_js = n.endswith(".js") or b"<script" in low or b"function(" in low or b"eval(" in low
    is_ps = n.endswith(".ps1") or b"powershell" in low or b"invoke-webrequest" in low or b"downloadstring" in low
    is_vbs = n.endswith(".vbs") or b"wscript" in low or b"cscript" in low
    is_py = n.endswith(".py") or b"import " in low or b"def " in low

    return {
        "is_ole2": bool(is_ole),
        "is_pe_executable_like": bool(is_pe),
        "is_zip_like": bool(is_zip),
        "is_rtf_like": bool(is_rtf),
        "is_pdf_like": bool(is_pdf),
        "is_javascript_like": bool(is_js),
        "is_powershell_like": bool(is_ps),
        "is_vbs_like": bool(is_vbs),
        "is_python_like": bool(is_py),
    }

def extract_docx_package_features(file_path: str) -> Tuple[dict, dict]:
    summary = {
        "zip_entry_count": 0,
        "xml_file_count": 0,
        "rels_file_count": 0,
        "media_file_count": 0,
        "bin_file_count": 0,

        "has_vba_project_bin": False,

        "embedded_object_count": 0,
        "embedded_ole_object_count": 0,
        "embedded_ole_with_macros_count": 0,
        "embedded_ole10native_count": 0,

        "embedded_pe_like_count": 0,
        "embedded_zip_like_count": 0,
        "embedded_rtf_like_count": 0,
        "embedded_pdf_like_count": 0,
        "embedded_script_like_count": 0,

        "embedded_max_size": 0,
        "embedded_max_entropy": 0.0,

        "external_url_count": 0,
        "suspicious_xml_keyword_total_hits": 0,

        # extra flags
        "has_customxml_flag": False,
        "customxml_part_count": 0,
        "activex_part_count": 0,
        "has_activex_flag": False,
        "has_embeddings_flag": False,
    }

    strings_part = {
        "external_urls": [],
        "external_domains": [],
        "suspicious_xml_keyword_hits": {},
        "embedded_objects": [],
    }

    suspicious_keywords = [
        "javascript:",
        "mhtml:",
        "wscript.shell",
        "createobject",
        "powershell",
        "cmd.exe",
        "ddeauto",
        "includepicture",
        "urldownloadtofile",
        "winhttp.winhttprequest",
        "msxml2.xmlhttp",
        "adodb.stream",
        "location.href",
        "window.location",
        "document.location",
        "targetmode=\"external\"",
    ]
    suspicious_counts = {k: 0 for k in suspicious_keywords}
    external_url_set = set()

    def _scan_text_part(name: str, text: str):
        # urls
        urls = re.findall(r"https?://[^\s\"']+", text, flags=re.IGNORECASE)
        for u in urls:
            external_url_set.add(u)
        tl = text.lower()
        for kw in suspicious_keywords:
            c = tl.count(kw)
            if c:
                suspicious_counts[kw] += c

    try:
        with zipfile.ZipFile(file_path, "r") as z:
            namelist = z.namelist()
            summary["zip_entry_count"] = len(namelist)

            # quick presence checks
            summary["customxml_part_count"] = len([n for n in namelist if n.lower().startswith("customxml/")])
            summary["has_customxml_flag"] = summary["customxml_part_count"] > 0

            summary["activex_part_count"] = len([n for n in namelist if n.lower().startswith("word/activex/")])
            summary["has_activex_flag"] = summary["activex_part_count"] > 0

            summary["has_embeddings_flag"] = any(n.lower().startswith("word/embeddings/") for n in namelist)

            for name in namelist:
                lower = name.lower()

                if lower.endswith(".rels"):
                    summary["rels_file_count"] += 1
                elif lower.endswith((".xml", ".vml")):
                    summary["xml_file_count"] += 1

                if "/media/" in lower:
                    summary["media_file_count"] += 1
                if lower.endswith(".bin"):
                    summary["bin_file_count"] += 1

                if "vbaproject.bin" in lower:
                    summary["has_vba_project_bin"] = True

                # scan text parts for url/keywords
                if lower.endswith((".xml", ".rels", ".vml")):
                    try:
                        data = z.read(name)
                        text = data.decode("utf-8", errors="ignore")
                    except Exception:
                        text = ""
                    _scan_text_part(name, text)

                # embedded binary objects candidates
                is_embedded = (
                    "embeddings/" in lower
                    or "activex/" in lower
                    or "oleobject" in lower
                    or lower.endswith(".bin") and ("word/" in lower)
                )

                if lower.endswith(".bin") and is_embedded:
                    summary["embedded_object_count"] += 1
                    try:
                        data = z.read(name)
                    except Exception:
                        continue

                    ent = shannon_entropy(data)
                    summary["embedded_max_size"] = max(summary["embedded_max_size"], len(data))
                    summary["embedded_max_entropy"] = max(summary["embedded_max_entropy"], ent)

                    flags = _guess_payload_flags(data, name)

                    if flags["is_ole2"]:
                        summary["embedded_ole_object_count"] += 1
                    if flags["is_pe_executable_like"]:
                        summary["embedded_pe_like_count"] += 1
                    if flags["is_zip_like"]:
                        summary["embedded_zip_like_count"] += 1
                    if flags["is_rtf_like"]:
                        summary["embedded_rtf_like_count"] += 1
                    if flags["is_pdf_like"]:
                        summary["embedded_pdf_like_count"] += 1
                    if flags["is_javascript_like"] or flags["is_powershell_like"] or flags["is_vbs_like"] or flags["is_python_like"]:
                        summary["embedded_script_like_count"] += 1

                    text_sample = safe_decode_latin1(data)
                    urls_bin = re.findall(r"https?://[^\s\"']+", text_sample, flags=re.IGNORECASE)
                    ips_bin = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text_sample)

                    b64 = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", text_sample)
                    hx = re.findall(r"\b[0-9a-fA-F]{40,}\b", text_sample)
                    b64 = list(dict.fromkeys(b64))
                    hx = list(dict.fromkeys(hx))

                    cs_sum, cs = detect_code_snippets(text_sample)

                    obj_entry = {
                        "name": name,
                        "size_bytes": len(data),
                        "sha256": sha256_bytes(data),
                        "entropy": float(ent),
                        "printable_ratio": float(printable_ratio_bytes(data)),
                        "null_byte_ratio": float(null_byte_ratio(data)),
                        "flags": flags,
                        "urls": urls_bin[:300],
                        "ip_like_list": ips_bin[:300],
                        "base64_candidates": b64[:200],
                        "hex_candidates": hx[:200],
                        "code_snippet_summary": cs_sum,
                        "code_snippets": cs,
                    }

                    is_textish = (obj_entry["printable_ratio"] >= 0.70 and obj_entry["null_byte_ratio"] < 0.10)
                    obj_entry["is_textish"] = bool(is_textish)
                    if is_textish:
                        t = text_sample
                        if len(t) > MAX_TEXT_CHARS:
                            t = t[:MAX_TEXT_CHARS] + "\n...[TRUNCATED]..."
                        obj_entry["text_preview"] = t
                    else:
                        obj_entry["binary_hexdump_preview"] = hexdump_preview(data)

                    # nested: if OLE, try VBA + Ole10Native
                    if flags["is_ole2"]:
                        vba_summary, vba_strings = extract_vba_from_ole_bytes(data, source_name=name)
                        obj_entry["vba_summary"] = vba_summary
                        obj_entry["vba_strings"] = vba_strings
                        if vba_summary.get("has_macros"):
                            summary["embedded_ole_with_macros_count"] += 1

                        ole10 = extract_ole10native_from_ole_bytes(data, source_name=name)
                        obj_entry["ole10native"] = ole10
                        if isinstance(ole10, dict):
                            summary["embedded_ole10native_count"] += int(ole10.get("ole10native_object_count", 0))

                    strings_part["embedded_objects"].append(obj_entry)

        strings_part["external_urls"] = sorted(list(external_url_set))[:1000]
        strings_part["external_domains"] = sorted(list({get_domain(u) for u in strings_part["external_urls"] if get_domain(u)}))[:1000]
        summary["external_url_count"] = len(strings_part["external_urls"])

        actual_hits = {k: v for k, v in suspicious_counts.items() if v > 0}
        strings_part["suspicious_xml_keyword_hits"] = actual_hits
        summary["suspicious_xml_keyword_total_hits"] = sum(actual_hits.values())

    except Exception as e:
        summary["error"] = f"docx_package_error: {e}"

    return summary, strings_part


# ================== RAW TEXT FEATURES (WHOLE FILE) ==================
def extract_raw_text_features(file_path: str) -> Tuple[dict, dict]:
    summary = {
        "raw_size_bytes": 0,
        "url_count": 0,
        "ip_like_count": 0,
        "script_keyword_total_hits": 0,
        "base64_candidate_count": 0,
        "hex_candidate_count": 0,
        "carved_suspicious_keyword_count": 0,
        "code_snippet_total_count": 0,
        "dde_line_count": 0,
    }
    strings = {
        "urls": [],
        "ip_like_list": [],
        "script_keyword_hits": {},
        "base64_candidates": [],
        "hex_candidates": [],
        "suspicious_keyword_hits": {},
        "dde_lines": [],
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

    base64_candidates = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", text)
    base64_candidates = list(dict.fromkeys(base64_candidates))
    strings["base64_candidates"] = base64_candidates
    summary["base64_candidate_count"] = len(base64_candidates)

    hex_candidates = re.findall(r"\b[0-9a-fA-F]{40,}\b", text)
    hex_candidates = list(dict.fromkeys(hex_candidates))
    strings["hex_candidates"] = hex_candidates
    summary["hex_candidate_count"] = len(hex_candidates)

    SUS = [
        "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin",
        "invoke-webrequest", "downloadstring", "new-object net.webclient",
        "wscript.shell", "createobject", "adodb.stream", "urldownloadtofile",
        "location.href", "window.location", "document.location",
        "frombase64string", "encodedcommand", "-enc", "ddeauto", "includepicture",
    ]
    sus_hits = {k: [] for k in SUS}
    dde_lines = []
    for line in text.splitlines():
        ll = line.lower()
        if "ddeauto" in ll or " dde " in ll:
            dde_lines.append(line.strip())
        for k in SUS:
            if k in ll:
                sus_hits[k].append(line.strip())

    sus_hits = {k: v for k, v in sus_hits.items() if v}
    strings["suspicious_keyword_hits"] = sus_hits
    summary["carved_suspicious_keyword_count"] = sum(len(v) for v in sus_hits.values())

    dde_lines = dde_lines[:200]
    strings["dde_lines"] = dde_lines
    summary["dde_line_count"] = len(dde_lines)

    cs_sum, cs = detect_code_snippets(text)
    strings["code_snippet_summary"] = cs_sum
    strings["code_snippets"] = cs
    summary["code_snippet_total_count"] = cs_sum.get("total_code_snippet_count", 0)

    return summary, strings


# ================== PROCESS SINGLE DOCX ==================
def process_single_docx(file_path: str) -> dict:
    label = get_label_from_path(file_path)
    file_info = get_file_basic_info(file_path)
    file_format = detect_file_format(file_path)

    errors: List[str] = []

    file_stats = extract_file_stats(file_path)
    if "error" in file_stats:
        errors.append(file_stats["error"])

    raw_summary, raw_strings = extract_raw_text_features(file_path)
    if "error" in raw_summary:
        errors.append(raw_summary["error"])

    vba_summary, vba_strings = extract_vba_from_docx(file_path)
    if "error" in vba_summary:
        errors.append(vba_summary["error"])

    if file_format == "zip_like":
        docx_meta = extract_docx_metadata(file_path)
        pkg_summary, pkg_strings = extract_docx_package_features(file_path)
        rels = extract_relationships(file_path)
        xml_ind = extract_xml_indicators(file_path)

        for sec in (docx_meta, pkg_summary, rels, xml_ind):
            if isinstance(sec, dict) and "error" in sec:
                errors.append(sec["error"])
    else:
        docx_meta = {"note": "Not a ZIP/OOXML container; DOCX-level features not applicable."}
        pkg_summary, pkg_strings = ({"note": "Skipped (not OOXML)"}, {})
        rels = {"note": "Skipped (not OOXML)"}
        xml_ind = {"note": "Skipped (not OOXML)"}

    # Flat ML-friendly features (keyword set)
    features = {
        "file_size_bytes": file_info.get("file_size_bytes", 0),
        "sha256": file_info.get("sha256", ""),
        "magic_mismatch": file_stats.get("magic_mismatch", False),
        "parse_errors_count": len(errors),

        "file_entropy": file_stats.get("file_entropy", 0.0),
        "entropy_suspicious_flag": file_stats.get("entropy_suspicious_flag", False),
        "printable_ratio": file_stats.get("printable_ratio", 0.0),
        "null_byte_ratio": file_stats.get("null_byte_ratio", 0.0),

        "zip_entry_count": pkg_summary.get("zip_entry_count", 0) if isinstance(pkg_summary, dict) else 0,
        "xml_file_count": pkg_summary.get("xml_file_count", 0) if isinstance(pkg_summary, dict) else 0,
        "rels_file_count": pkg_summary.get("rels_file_count", 0) if isinstance(pkg_summary, dict) else 0,
        "media_file_count": pkg_summary.get("media_file_count", 0) if isinstance(pkg_summary, dict) else 0,
        "bin_file_count": pkg_summary.get("bin_file_count", 0) if isinstance(pkg_summary, dict) else 0,

        "has_vba_project_bin": pkg_summary.get("has_vba_project_bin", False) if isinstance(pkg_summary, dict) else False,

        "embedded_object_count": pkg_summary.get("embedded_object_count", 0) if isinstance(pkg_summary, dict) else 0,
        "embedded_ole_object_count": pkg_summary.get("embedded_ole_object_count", 0) if isinstance(pkg_summary, dict) else 0,
        "embedded_ole_with_macros_count": pkg_summary.get("embedded_ole_with_macros_count", 0) if isinstance(pkg_summary, dict) else 0,
        "embedded_ole10native_count": pkg_summary.get("embedded_ole10native_count", 0) if isinstance(pkg_summary, dict) else 0,

        "embedded_pe_like_count": pkg_summary.get("embedded_pe_like_count", 0) if isinstance(pkg_summary, dict) else 0,
        "embedded_zip_like_count": pkg_summary.get("embedded_zip_like_count", 0) if isinstance(pkg_summary, dict) else 0,
        "embedded_rtf_like_count": pkg_summary.get("embedded_rtf_like_count", 0) if isinstance(pkg_summary, dict) else 0,
        "embedded_pdf_like_count": pkg_summary.get("embedded_pdf_like_count", 0) if isinstance(pkg_summary, dict) else 0,
        "embedded_script_like_count": pkg_summary.get("embedded_script_like_count", 0) if isinstance(pkg_summary, dict) else 0,
        "embedded_max_size": pkg_summary.get("embedded_max_size", 0) if isinstance(pkg_summary, dict) else 0,
        "embedded_max_entropy": pkg_summary.get("embedded_max_entropy", 0.0) if isinstance(pkg_summary, dict) else 0.0,

        "external_url_count": pkg_summary.get("external_url_count", 0) if isinstance(pkg_summary, dict) else 0,
        "suspicious_xml_keyword_total_hits": pkg_summary.get("suspicious_xml_keyword_total_hits", 0) if isinstance(pkg_summary, dict) else 0,

        "has_customxml_flag": pkg_summary.get("has_customxml_flag", False) if isinstance(pkg_summary, dict) else False,
        "customxml_part_count": pkg_summary.get("customxml_part_count", 0) if isinstance(pkg_summary, dict) else 0,
        "has_activex_flag": pkg_summary.get("has_activex_flag", False) if isinstance(pkg_summary, dict) else False,
        "activex_part_count": pkg_summary.get("activex_part_count", 0) if isinstance(pkg_summary, dict) else 0,
        "has_embeddings_flag": pkg_summary.get("has_embeddings_flag", False) if isinstance(pkg_summary, dict) else False,

        # relationships summary
        "rels_total_count": rels.get("rels_total_count", 0) if isinstance(rels, dict) else 0,
        "rels_external_count": rels.get("rels_external_count", 0) if isinstance(rels, dict) else 0,
        "rels_external_url_count": rels.get("rels_external_url_count", 0) if isinstance(rels, dict) else 0,
        "has_remote_template_flag": rels.get("has_remote_template_flag", False) if isinstance(rels, dict) else False,
        "has_external_hyperlink_flag": rels.get("has_external_hyperlink_flag", False) if isinstance(rels, dict) else False,
        "has_external_image_rel_flag": rels.get("has_external_image_rel_flag", False) if isinstance(rels, dict) else False,
        "has_oleobject_rel_flag": rels.get("has_oleobject_rel_flag", False) if isinstance(rels, dict) else False,
        "has_package_rel_flag": rels.get("has_package_rel_flag", False) if isinstance(rels, dict) else False,

        # xml indicators
        "xml_instrtext_count": xml_ind.get("xml_instrtext_count", 0) if isinstance(xml_ind, dict) else 0,
        "dde_field_flag": xml_ind.get("dde_field_flag", False) if isinstance(xml_ind, dict) else False,
        "field_cmd_suspicious_count": xml_ind.get("field_cmd_suspicious_count", 0) if isinstance(xml_ind, dict) else 0,
        "xml_external_url_count": xml_ind.get("xml_external_url_count", 0) if isinstance(xml_ind, dict) else 0,
        "xml_hyperlink_count": xml_ind.get("xml_hyperlink_count", 0) if isinstance(xml_ind, dict) else 0,
        "include_picture_field_count": xml_ind.get("include_picture_field_count", 0) if isinstance(xml_ind, dict) else 0,

        # vba (docx rarely; still keep)
        "has_vba": vba_summary.get("has_macros", False),
        "vba_module_count": len(set(vba_strings.get("macro_module_names", []) or [])),
        "vba_line_count": vba_summary.get("vba_line_count", 0),
        "vba_autoexec_count": vba_summary.get("autoexec_keyword_count", 0),
        "vba_suspicious_api_count": vba_summary.get("suspicious_keyword_count", 0),
        "vba_url_count": vba_summary.get("url_count", 0),
        "vba_base64_like_count": vba_summary.get("vba_base64_like_count", 0),
        "vba_hex_like_count": vba_summary.get("vba_hex_like_count", 0),
        "vba_high_entropy_string_count": vba_summary.get("vba_high_entropy_string_count", 0),
        "vba_execute_eval_flag": vba_summary.get("vba_execute_eval_flag", False),
        "vba_powershell_cmd_count": vba_summary.get("vba_powershell_cmd_count", 0),
        "vba_code_snippet_total_count": vba_summary.get("vba_code_snippet_total_count", 0),

        # raw carve
        "carved_url_count": raw_summary.get("url_count", 0),
        "carved_ip_count": raw_summary.get("ip_like_count", 0),
        "carved_suspicious_keyword_count": raw_summary.get("carved_suspicious_keyword_count", 0),
        "raw_code_snippet_total_count": raw_summary.get("code_snippet_total_count", 0),
        "raw_dde_line_count": raw_summary.get("dde_line_count", 0),
    }

    record = {
        "label": label,
        "file_info": file_info,
        "file_format": file_format,

        "features": features,
        "file_stats": file_stats,

        "docx_metadata": docx_meta,
        "relationships": rels,
        "xml_indicators": xml_ind,

        "vba_summary": vba_summary,
        "vba_strings": vba_strings,

        "package_summary": pkg_summary,
        "package_strings": pkg_strings,

        "raw_text_summary": raw_summary,
        "raw_text_strings": raw_strings,

        "errors": errors,
    }

    safe_record = make_json_safe(record)
    out_path = os.path.join(OUTPUT_ROOT, os.path.basename(file_path) + ".json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(safe_record, f, ensure_ascii=False, indent=2)

    print(f"[OK] {file_path} -> {out_path}")
    return safe_record


# ================== MAIN: SCAN ENTIRE DOCX DATASET ==================
def iter_docx_files():
    for label_dir in ["malicious", "benign"]:
        base_dir = os.path.join(DOCX_ROOT, label_dir)
        if not os.path.isdir(base_dir):
            print(f"[WARN] Folder not found: {base_dir}")
            continue
        for root, _, files in os.walk(base_dir):
            for fname in files:
                lower = fname.lower()
                if lower.endswith(".docx") or lower.endswith(".docm"):
                    yield os.path.join(root, fname)

def main():
    print(f"[*] DOCX extraction started at {datetime.now()}")
    count = 0
    for file_path in iter_docx_files():
        process_single_docx(file_path)
        count += 1
    print(f"[*] Finished at {datetime.now()}, total files processed: {count}")

if __name__ == "__main__":
    main()
