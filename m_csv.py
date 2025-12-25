import os
import json
import csv
import hashlib
from collections import defaultdict
from typing import Any, Dict, List, Tuple

# ================== CONFIG ==================
DATASET_ROOT = "/home/burak/Desktop/malicious_dataset"

# JSON result klasörlerini otomatik bulacak (ör: doc_extraction_results, docx_extraction_results ...)
RESULT_DIR_HINTS = [
    "malicious_doc_extraction_results",
    "malicious_docx_extraction_results",
    "malicious_docm_extraction_results",
]

OUT_DIR = os.path.join(DATASET_ROOT, "summary_csv")
os.makedirs(OUT_DIR, exist_ok=True)

# “first bytes” yaklaşımı
PREFIX_LEN = 32          # base64/hex/snippet/url için ilk kaç karakter CSV’ye girsin
FIRST_K = 5              # her listeden CSV’ye basılacak ilk kaç örnek
MAX_COLLECT = 5000       # bir dosyada toplanacak max item (çok büyürse dur)
# ===========================================

SKIP_KEYS_CONTAINING = {
    "all_vba_code", "payload_text", "text_preview", "binary_hexdump_preview"
}

def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()

def prefix(s: str, n: int = PREFIX_LEN) -> str:
    s = s.replace("\n", "\\n").replace("\r", "\\r")
    return s[:n]

def safe_get(d: dict, *keys, default=None):
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur

def detect_format_from_path(json_path: str) -> str:
    p = json_path.lower()
    if "docx_extraction_results" in p:
        return "docx"
    if "docm_extraction_results" in p:
        return "docm"
    if "doc_extraction_results" in p:
        return "doc"
    # fallback: dosyanın içinden ext bak
    return "unknown"

def walk_json_files() -> List[str]:
    paths = []
    for root, dirs, files in os.walk(DATASET_ROOT):
        base = os.path.basename(root)
        if base in RESULT_DIR_HINTS:
            for f in files:
                if f.lower().endswith(".json"):
                    paths.append(os.path.join(root, f))
    return sorted(paths)

def iter_kv(obj: Any):
    """Recursively yield (key, value) for dict/list; used to collect lists."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k, v
            yield from iter_kv(v)
    elif isinstance(obj, list):
        for it in obj:
            yield from iter_kv(it)

def collect_strings_by_key(root: dict, target_keys: set) -> List[str]:
    out = []
    for k, v in iter_kv(root):
        if any(sk in str(k).lower() for sk in SKIP_KEYS_CONTAINING):
            continue
        if str(k) in target_keys:
            if isinstance(v, list):
                for s in v:
                    if isinstance(s, str) and s:
                        out.append(s)
                        if len(out) >= MAX_COLLECT:
                            return out
    return out

def collect_code_snippets(root: dict) -> List[str]:
    """
    code_snippets genelde dict(dict(list)) yapısında.
    Tüm snippet listelerini tek listeye indirger.
    """
    out = []
    for k, v in iter_kv(root):
        if any(sk in str(k).lower() for sk in SKIP_KEYS_CONTAINING):
            continue
        if str(k).endswith("code_snippets") and isinstance(v, dict):
            for _, lst in v.items():
                if isinstance(lst, list):
                    for s in lst:
                        if isinstance(s, str) and s:
                            out.append(s)
                            if len(out) >= MAX_COLLECT:
                                return out
    return out

def aggregate_list(lst: List[str], name: str) -> Dict[str, Any]:
    """
    CSV’ye koymak için: count/unique/max_len/avg_len + first_k prefix + first_k hash
    """
    lst = [x for x in lst if isinstance(x, str) and x]
    count = len(lst)
    uniq = list(dict.fromkeys(lst))  # stable unique
    uniq_count = len(uniq)
    lengths = [len(x) for x in lst] if lst else []
    max_len = max(lengths) if lengths else 0
    avg_len = (sum(lengths) / len(lengths)) if lengths else 0.0

    first = uniq[:FIRST_K]
    prefixes = [prefix(x) for x in first]
    hashes = [sha256_text(x) for x in first]

    out = {
        f"{name}_count": count,
        f"{name}_unique_count": uniq_count,
        f"{name}_max_len": max_len,
        f"{name}_avg_len": round(avg_len, 3),
        f"{name}_first{FIRST_K}_prefixes": " | ".join(prefixes),
        f"{name}_first{FIRST_K}_sha256": " | ".join(hashes),
    }
    return out

def flatten_features_block(j: dict) -> Dict[str, Any]:
    """
    Yeni docx scriptinde 'features' vardı; eski doc/docx scriptlerinde yok.
    - varsa features içini direkt alır
    - yoksa bazı özet alanları kendisi çıkarır
    """
    out = {}
    features = j.get("features")
    if isinstance(features, dict):
        # zaten ML-friendly
        for k, v in features.items():
            out[k] = v
        return out

    # Fallback (eski şema): temel sayımlar
    out["file_size_bytes"] = safe_get(j, "file_info", "file_size_bytes", default=0)
    out["file_format"] = j.get("file_format", "")
    out["parse_errors_count"] = len(j.get("errors", []) or [])

    vba = j.get("vba_summary") or {}
    raw = j.get("raw_text_summary") or {}
    pkg = j.get("package_summary") or {}

    # VBA
    out["has_vba"] = bool(vba.get("has_macros", False))
    out["vba_line_count"] = int(vba.get("vba_line_count", 0) or 0)
    out["vba_autoexec_count"] = int(vba.get("autoexec_keyword_count", 0) or 0)
    out["vba_suspicious_api_count"] = int(vba.get("suspicious_keyword_count", 0) or 0)
    out["vba_url_count"] = int(vba.get("url_count", 0) or 0)

    # Raw
    out["carved_url_count"] = int(raw.get("url_count", 0) or 0)
    out["carved_ip_count"] = int(raw.get("ip_like_count", 0) or 0)
    out["base64_candidate_count"] = int(raw.get("base64_candidate_count", 0) or 0)
    out["hex_candidate_count"] = int(raw.get("hex_candidate_count", 0) or 0)

    # Package (docx/docm için)
    if isinstance(pkg, dict):
        for k in [
            "zip_entry_count", "xml_file_count", "rels_file_count", "media_file_count", "bin_file_count",
            "has_vba_project_bin", "embedded_object_count", "external_url_count"
        ]:
            if k in pkg:
                out[k] = pkg.get(k)
    return out

def build_row(j: dict, json_path: str) -> Dict[str, Any]:
    fmt = detect_format_from_path(json_path)
    label = j.get("label", "unknown")

    fi = j.get("file_info") or {}
    row = {
        "format": fmt,
        "label": label,
        "json_path": json_path,
        "file_name": fi.get("file_name", ""),
        "file_ext": fi.get("file_ext", ""),
        "file_path": fi.get("file_path", ""),
    }

    # feature block
    row.update(flatten_features_block(j))

    # ---- Collect variable-length artifacts (URLs, IPs, Base64, Hex, Snippets) ----
    # URL kaynak anahtarları (farklı scriptlerde farklı yerlerde olabiliyor)
    url_keys = {
        "urls", "external_urls", "rels_external_urls"
    }
    ip_keys = {
        "ip_like_list"
    }
    b64_keys = {
        "base64_candidates", "vba_base64_candidates"
    }
    hex_keys = {
        "hex_candidates", "vba_hex_candidates"
    }

    urls = collect_strings_by_key(j, url_keys)
    ips = collect_strings_by_key(j, ip_keys)
    b64 = collect_strings_by_key(j, b64_keys)
    hx = collect_strings_by_key(j, hex_keys)
    snippets = collect_code_snippets(j)

    # Aggregations (CSV-friendly)
    row.update(aggregate_list(urls, "urls_total"))
    row.update(aggregate_list(ips, "ips_total"))
    row.update(aggregate_list(b64, "base64_total"))
    row.update(aggregate_list(hx, "hex_total"))
    row.update(aggregate_list(snippets, "snippets_total"))

    return row

def write_csv(path: str, rows: List[Dict[str, Any]]):
    if not rows:
        return
    # union columns
    cols = set()
    for r in rows:
        cols.update(r.keys())
    cols = sorted(cols)

    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow(r)

def main():
    json_files = walk_json_files()
    if not json_files:
        print("[WARN] No JSON files found under dataset root. Check RESULT_DIR_HINTS or paths.")
        return

    groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)

    for jp in json_files:
        try:
            with open(jp, "r", encoding="utf-8") as f:
                j = json.load(f)
        except Exception as e:
            print(f"[WARN] Failed to read JSON: {jp} ({e})")
            continue

        row = build_row(j, jp)
        fmt = row.get("format", "unknown")
        label = row.get("label", "unknown")
        groups[(fmt, label)].append(row)

    # write per group
    for (fmt, label), rows in groups.items():
        out_name = f"{fmt}_{label}_summary.csv"
        out_path = os.path.join(OUT_DIR, out_name)
        write_csv(out_path, rows)
        print(f"[OK] {out_path}  ({len(rows)} rows)")

    print(f"[*] Done. CSVs are under: {OUT_DIR}")

if __name__ == "__main__":
    main()
