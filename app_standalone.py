#!/usr/bin/env python3
"""
app.py — Streamlit UI for datamask (reversible sensitive-data masking).

Run:  streamlit run app.py
Needs datamask.py in the same directory.

Tabs:
  1. Scan   — upload files, see detected sensitive data + recommendations
  2. Mask   — tokenize files, download masked copies + mapping.json (codebook)
  3. Decode — upload AI output (pptx/docx/xlsx/csv) + mapping.json, download restored
"""

import io
import json
import os
import tempfile
import zipfile

import streamlit as st

# ==== inlined from datamask.py ====
import csv as csv_mod
import io
import json
import os
import re
import sys
from collections import OrderedDict
from datetime import datetime, timezone

# ---------------------------------------------------------------- detectors

PRIVATE_NETS = re.compile(
    r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.)"
)

def _valid_ipv4(s: str) -> bool:
    parts = s.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)

# Order matters: more specific first (email before domain, FQDN before hostname).
DETECTORS = [
    # (category, token prefix, regex, post-filter)
    ("email",    "MAILX", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), None),
    ("ipv4",     "IPX",   re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), _valid_ipv4),
    ("ipv6",     "IP6X",  re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b"),
        lambda s: not re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", s)),
    ("mac",      "MACX",  re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"), None),
    # Windows-style hostnames: DESKTOP-XXXX, SRV-*, WIN-*, DC01, LAPTOP-...
    ("hostname", "HOSTX", re.compile(
        r"\b(?:DESKTOP|LAPTOP|WIN|SRV|SVR|DC|PC|WS|HOST|VM|APP|DB|WEB|MAIL|FW|SW|RTR|PRD|DEV|UAT)"
        r"[-_][A-Za-z0-9][A-Za-z0-9-_]{1,30}\b", re.IGNORECASE), None),
    # FQDN (internal domains etc.) — post-filter drops common file extensions
    ("fqdn",     "FQDNX", re.compile(
        r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){2,}[A-Za-z]{2,}\b"),
        lambda s: not re.search(r"\.(?:exe|dll|csv|xlsx|docx|pptx|txt|log|json|xml|py|sh|js|zip|png|jpg)$", s, re.I)),
    # DOMAIN\username
    ("username", "USERX", re.compile(r"\b[A-Za-z][A-Za-z0-9_-]{1,20}\\[A-Za-z][A-Za-z0-9._-]{2,30}\b"), None),
    # key=value contextual usernames: user=jdoe, username: budi.s, account="ops_admin"
    ("username", "USERX", re.compile(
        r"(?i)\b(?:user(?:name)?|account|login|logon|acct)\s*[:=]\s*\"?([A-Za-z][A-Za-z0-9._-]{2,30})\"?"), None),
]

MASK_RECOMMENDATION = {
    "ipv4":     "Tokenize (reversible). If sharing externally without codebook: mask last octet (10.1.2.x).",
    "ipv6":     "Tokenize (reversible). External: truncate to /48 prefix.",
    "hostname": "Tokenize (reversible). External: role-based alias (WEB-SRV-A).",
    "fqdn":     "Tokenize (reversible). External: replace internal domain with example.internal.",
    "username": "Tokenize (reversible). Never share real usernames outside the org — high phishing value.",
    "email":    "Tokenize (reversible). External: hash local-part, keep domain if public.",
    "mac":      "Tokenize (reversible). External: keep OUI (vendor) bytes, mask last 3 octets.",
}

# ---------------------------------------------------------------- codebook

class Codebook:
    def __init__(self, path=None):
        self.map = OrderedDict()      # original -> token
        self.rev = OrderedDict()      # token -> original
        self.meta = {"created": datetime.now(timezone.utc).isoformat(), "tool": "datamask v1.0"}
        self.counters = {}
        if path and os.path.exists(path):
            with open(path) as f:
                data = json.load(f)
            self.meta = data.get("meta", self.meta)
            for orig, entry in data.get("entries", {}).items():
                self.map[orig] = entry["token"]
                self.rev[entry["token"]] = orig
                self._bump_counter(entry["token"])
            self.categories = {o: e["category"] for o, e in data.get("entries", {}).items()}
        else:
            self.categories = {}

    def _bump_counter(self, token):
        m = re.match(r"([A-Z0-9]+?X)(\d+)$", token)
        if m:
            pfx, n = m.group(1), int(m.group(2))
            self.counters[pfx] = max(self.counters.get(pfx, 0), n)

    def token_for(self, original, category, prefix):
        if original in self.map:
            return self.map[original]
        self.counters[prefix] = self.counters.get(prefix, 0) + 1
        token = f"{prefix}{self.counters[prefix]:03d}"
        self.map[original] = token
        self.rev[token] = original
        self.categories[original] = category
        return token

    def save(self, path):
        entries = {o: {"token": t, "category": self.categories.get(o, "?"),
                       "recommendation": MASK_RECOMMENDATION.get(self.categories.get(o, ""), "Tokenize (reversible).")}
                   for o, t in self.map.items()}
        with open(path, "w") as f:
            json.dump({"meta": self.meta, "entries": entries}, f, indent=2)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

# ---------------------------------------------------------------- core replace

def find_all(text):
    """Yield (category, prefix, match_text) for every detection in text."""
    out = []
    for cat, pfx, rx, flt in DETECTORS:
        for m in rx.finditer(text):
            val = m.group(1) if m.groups() else m.group(0)
            if flt and not flt(val):
                continue
            out.append((cat, pfx, val))
    return out

def mask_text(text, cb: Codebook):
    """Replace all detections in text with tokens. Longest-first to avoid partial overlap."""
    findings = find_all(text)
    if not findings:
        return text, 0
    # Assign tokens
    for cat, pfx, val in findings:
        cb.token_for(val, cat, pfx)
    # Replace longest originals first
    n = 0
    for orig in sorted({v for _, _, v in findings}, key=len, reverse=True):
        token = cb.map[orig]
        new = text.replace(orig, token)
        if new != text:
            n += text.count(orig)
            text = new
    return text, n

def unmask_text(text, cb: Codebook):
    n = 0
    for token in sorted(cb.rev, key=len, reverse=True):
        if token in text:
            n += text.count(token)
            text = text.replace(token, cb.rev[token])
    return text, n

# ---------------------------------------------------------------- file handlers

def _iter_docx_paragraphs(doc):
    """Yield every paragraph in body, tables (nested), headers, footers."""
    from docx.table import Table
    from docx.text.paragraph import Paragraph
    def walk(parent):
        for p in parent.paragraphs:
            yield p
        for t in parent.tables:
            for row in t.rows:
                for cell in row.cells:
                    yield from walk(cell)
    yield from walk(doc)
    for sec in doc.sections:
        for part in (sec.header, sec.footer):
            yield from walk(part)

def _replace_in_paragraph(par, fn):
    """Apply fn(text)->(text,count) to full paragraph text, preserving run 0 formatting
    when a match spans runs. Only rewrites the paragraph if something changed."""
    full = par.text
    new, n = fn(full)
    if n == 0:
        return 0
    # Try run-by-run first (keeps formatting perfectly when matches are within a run)
    total_in_runs = 0
    for run in par.runs:
        rnew, rn = fn(run.text)
        if rn:
            run.text = rnew
            total_in_runs += rn
    if par.text == new:
        return n
    # Cross-run match remains: collapse into first run
    if par.runs:
        par.runs[0].text = new
        for run in par.runs[1:]:
            run.text = ""
    return n

def process_docx(path, out_path, fn):
    import docx
    doc = docx.Document(path)
    count = 0
    for par in _iter_docx_paragraphs(doc):
        count += _replace_in_paragraph(par, fn)
    doc.save(out_path)
    return count

def process_pptx(path, out_path, fn):
    from pptx import Presentation
    prs = Presentation(path)
    count = 0
    def handle_tf(tf):
        nonlocal count
        for par in tf.paragraphs:
            full = "".join(r.text for r in par.runs)
            new, n = fn(full)
            if n == 0:
                continue
            done_in_runs = 0
            for r in par.runs:
                rnew, rn = fn(r.text)
                if rn:
                    r.text = rnew
                    done_in_runs += rn
            cur = "".join(r.text for r in par.runs)
            if cur != new and par.runs:
                par.runs[0].text = new
                for r in par.runs[1:]:
                    r.text = ""
            count += n
    def handle_shape(shape):
        if shape.has_text_frame:
            handle_tf(shape.text_frame)
        if shape.shape_type == 6:  # group
            for s in shape.shapes:
                handle_shape(s)
        if getattr(shape, "has_table", False) and shape.has_table:
            for row in shape.table.rows:
                for cell in row.cells:
                    handle_tf(cell.text_frame)
    for slide in prs.slides:
        for shape in slide.shapes:
            handle_shape(shape)
        if slide.has_notes_slide:
            handle_tf(slide.notes_slide.notes_text_frame)
    prs.save(out_path)
    return count

def process_xlsx(path, out_path, fn):
    import openpyxl
    wb = openpyxl.load_workbook(path)  # formulas preserved; we only touch strings
    count = 0
    for ws in wb.worksheets:
        for row in ws.iter_rows():
            for cell in row:
                if isinstance(cell.value, str) and not cell.value.startswith("="):
                    new, n = fn(cell.value)
                    if n:
                        cell.value = new
                        count += n
        # sheet name itself can contain hostnames
        new_title, n = fn(ws.title)
        if n:
            ws.title = new_title[:31]
            count += n
    wb.save(out_path)
    return count

def process_textlike(path, out_path, fn):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    new, n = fn(text)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(new)
    return n

HANDLERS = {
    ".docx": process_docx,
    ".pptx": process_pptx,
    ".xlsx": process_xlsx,
    ".xlsm": process_xlsx,
    ".csv":  process_textlike,
    ".tsv":  process_textlike,
    ".txt":  process_textlike,
    ".log":  process_textlike,
    ".json": process_textlike,
    ".xml":  process_textlike,
    ".md":   process_textlike,
}

def extract_text(path):
    """Read all visible text from a file for scan-only mode."""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".docx":
        import docx
        doc = docx.Document(path)
        return "\n".join(p.text for p in _iter_docx_paragraphs(doc))
    if ext == ".pptx":
        from pptx import Presentation
        prs = Presentation(path)
        chunks = []
        for slide in prs.slides:
            for shape in slide.shapes:
                if shape.has_text_frame:
                    chunks.append(shape.text_frame.text)
                if getattr(shape, "has_table", False) and shape.has_table:
                    for row in shape.table.rows:
                        for cell in row.cells:
                            chunks.append(cell.text)
        return "\n".join(chunks)
    if ext in (".xlsx", ".xlsm"):
        import openpyxl
        wb = openpyxl.load_workbook(path, read_only=True)
        chunks = []
        for ws in wb.worksheets:
            for row in ws.iter_rows(values_only=True):
                chunks.extend(str(v) for v in row if isinstance(v, str))
        return "\n".join(chunks)
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


# ==== end inline ====


st.set_page_config(page_title="DataMask", page_icon="🛡️", layout="wide")
st.title("🛡️ DataMask — Reversible Masking for SOC Reports")
st.caption("Detect → Mask → kirim ke AI → Decode. Codebook (mapping.json) = kunci, jangan pernah ikut dikirim ke AI.")

SUPPORTED = tuple(HANDLERS.keys())


def _save_upload(uploaded):
    """Persist an uploaded file to a temp path, return path."""
    suffix = os.path.splitext(uploaded.name)[1].lower()
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    tmp.write(uploaded.getvalue())
    tmp.close()
    return tmp.name


def _process(uploaded_files, fn, suffix):
    """Run mask/unmask fn over uploads; return list of (name, bytes, count)."""
    results = []
    for up in uploaded_files:
        ext = os.path.splitext(up.name)[1].lower()
        handler = HANDLERS.get(ext)
        if not handler:
            results.append((up.name, None, f"unsupported type {ext}"))
            continue
        in_path = _save_upload(up)
        out_path = in_path + ".out" + ext
        n = handler(in_path, out_path, fn)
        with open(out_path, "rb") as f:
            data = f.read()
        os.unlink(in_path); os.unlink(out_path)
        stem, e = os.path.splitext(up.name)
        results.append((f"{stem}{suffix}{e}", data, n))
    return results


def _zip_results(results, extra=None):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data, _ in results:
            if data is not None:
                z.writestr(name, data)
        if extra:
            for name, data in extra.items():
                z.writestr(name, data)
    buf.seek(0)
    return buf


def codebook_from_json_str(s):
    """Build a Codebook from a pasted mapping.json string. Returns (cb, error)."""
    cb = Codebook()
    try:
        data = json.loads(s)
    except json.JSONDecodeError as e:
        return None, f"JSON tidak valid: {e}"
    entries = data.get("entries", data)  # accept full file or just the entries dict
    for orig, entry in entries.items():
        if isinstance(entry, dict) and "token" in entry:
            token, cat = entry["token"], entry.get("category", "?")
        elif isinstance(entry, str):     # also accept simple {"original": "TOKEN"}
            token, cat = entry, "?"
        else:
            continue
        cb.map[orig] = token
        cb.rev[token] = orig
        cb.categories[orig] = cat
        cb._bump_counter(token)
    if not cb.rev:
        return None, "Tidak ada entri token ditemukan di JSON."
    return cb, None


def mapping_input(label_prefix, key_prefix):
    """Upload-or-paste widget for mapping.json. Returns Codebook or None."""
    m = st.radio(f"{label_prefix} — sumber", ["📁 Upload", "📋 Paste JSON"],
                 horizontal=True, key=f"{key_prefix}_src")
    if m == "📁 Upload":
        up = st.file_uploader(f"{label_prefix} (mapping.json)", type=["json"],
                              key=f"{key_prefix}_up")
        if up:
            p = _save_upload(up)
            cb = Codebook(p)
            os.unlink(p)
            return cb
        return None
    pasted = st.text_area(f"{label_prefix} — paste isi mapping.json",
                          height=150, key=f"{key_prefix}_txt")
    if pasted.strip():
        cb, err = codebook_from_json_str(pasted)
        if err:
            st.error(err)
            return None
        st.success(f"Codebook loaded: {len(cb.map)} entri")
        return cb
    return None


def decode_table(text, cb):
    """Rows of (token, original, category, occurrences) for tokens present in text."""
    rows = []
    for token, orig in cb.rev.items():
        n = text.count(token)
        if n:
            rows.append({"Token": token, "Decoded to": orig,
                         "Category": cb.categories.get(orig, "?"), "Count": n})
    return sorted(rows, key=lambda r: r["Token"])


tab_scan, tab_mask, tab_decode = st.tabs(["🔍 1. Scan", "🎭 2. Mask (Encode)", "🔓 3. Decode (Unmask)"])

# ------------------------------------------------------------------ SCAN
with tab_scan:
    st.subheader("Deteksi data sensitif")
    mode = st.radio("Input", ["📁 Upload file", "📋 Paste text"], horizontal=True, key="scan_mode")

    if mode == "📋 Paste text":
        pasted = st.text_area("Paste teks di sini (log, email, chat, apapun)",
                              height=220, key="scan_txt")
        if pasted and st.button("Scan text", type="primary", key="scan_txt_btn"):
            agg = {}
            for cat, pfx, val in find_all(pasted):
                agg.setdefault(cat, set()).add(val)
            if not agg:
                st.success("Tidak ada data sensitif terdeteksi.")
            for cat in sorted(agg):
                st.markdown(f"**{cat.upper()}** ({len(agg[cat])} unique)")
                st.code(", ".join(sorted(agg[cat])), language=None)
            if agg:
                st.table([{"Category": c.upper(), "Unique": len(v),
                           "Recommendation": MASK_RECOMMENDATION.get(c, "")}
                          for c, v in sorted(agg.items())])

    ups = None
    if mode == "📁 Upload file":
        ups = st.file_uploader("Upload report files", type=[e.lstrip(".") for e in SUPPORTED],
                               accept_multiple_files=True, key="scan_up")
    if ups and st.button("Scan", type="primary"):
        grand = {}
        for up in ups:
            path = _save_upload(up)
            text = extract_text(path)
            os.unlink(path)
            agg = {}
            for cat, pfx, val in find_all(text):
                agg.setdefault(cat, set()).add(val)
            with st.expander(f"📄 {up.name} — {sum(len(v) for v in agg.values())} unique findings",
                             expanded=True):
                if not agg:
                    st.success("Tidak ada data sensitif terdeteksi.")
                for cat in sorted(agg):
                    grand.setdefault(cat, set()).update(agg[cat])
                    st.markdown(f"**{cat.upper()}** ({len(agg[cat])} unique)")
                    st.code(", ".join(sorted(agg[cat])), language=None)
        if grand:
            st.divider()
            st.subheader("Rekomendasi masking")
            st.table([{"Category": c.upper(), "Unique": len(v),
                       "Recommendation": MASK_RECOMMENDATION.get(c, "")}
                      for c, v in sorted(grand.items())])

# ------------------------------------------------------------------ MASK
with tab_mask:
    st.subheader("Tokenize / encode data sensitif")
    st.caption("Alur: 1) Scan → 2) review & pilih value yang mau di-encode (bisa hapus/tambah) → 3) Encode.")
    mode = st.radio("Input", ["📁 Upload file", "📋 Paste text"], horizontal=True, key="mask_mode")
    with st.expander("(Opsional) mapping.json lama — biar token konsisten antar batch"):
        prev_cb = mapping_input("Mapping lama", "mask_map")

    CAT_PREFIX = {cat: pfx for cat, pfx, _, _ in DETECTORS}
    CAT_PREFIX["custom"] = "CUSTX"
    CATS = list(CAT_PREFIX.keys())

    pasted, ups = None, None
    if mode == "📋 Paste text":
        pasted = st.text_area("Paste teks yang mau di-mask", height=200, key="mask_txt")
    else:
        ups = st.file_uploader("Upload files to mask", type=[e.lstrip(".") for e in SUPPORTED],
                               accept_multiple_files=True, key="mask_up")

    # ---- Step 1: scan
    if st.button("🔍 Scan dulu", type="primary", disabled=not (pasted or ups)):
        texts = []
        if pasted:
            texts.append(pasted)
        if ups:
            for up in ups:
                p = _save_upload(up)
                texts.append(extract_text(p))
                os.unlink(p)
        combined = "\n".join(texts)
        st.session_state["mask_scan_text"] = combined
        seen = {}
        for t in texts:
            for cat, pfx, val in find_all(t):
                seen.setdefault(val, cat)
        st.session_state["mask_rows"] = [
            {"Encode": True, "Value": v, "Category": c, "Matches": combined.count(v)}
            for v, c in sorted(seen.items())
        ]

    # ---- Step 2: review & select
    if st.session_state.get("mask_rows"):
        st.markdown("**Review findings** — uncheck yang nggak mau di-encode, "
                    "hapus baris (ikon 🗑), atau tambah baris baru untuk value custom "
                    "(nama klien, ticket ID, dll):")
        edited = st.data_editor(
            st.session_state["mask_rows"],
            column_config={
                "Encode": st.column_config.CheckboxColumn("Encode", default=True),
                "Value": st.column_config.TextColumn("Value", required=True),
                "Category": st.column_config.SelectboxColumn("Category", options=CATS,
                                                             default="custom"),
                "Matches": st.column_config.NumberColumn("Matches (saat scan)", disabled=True),
            },
            num_rows="dynamic", use_container_width=True, key="mask_editor",
        )
        selected = {r["Value"]: r.get("Category") or "custom"
                    for r in edited if r.get("Encode") and r.get("Value")}
        st.write(f"Terpilih: **{len(selected)}** dari {len(edited)} value")

        # live match check — recount against scanned text on every edit
        scan_text = st.session_state.get("mask_scan_text", "")
        if selected and scan_text:
            check = []
            zero = []
            for v, c in selected.items():
                hits = scan_text.count(v)
                check.append({"Value": v, "Category": c, "Matches": hits,
                              "Chars": len(v), "Chars total": hits * len(v)})
                if hits == 0:
                    zero.append(v)
            st.markdown("**Match check (live):**")
            st.dataframe(check, use_container_width=True)
            if zero:
                st.warning("⚠️ 0 match — cek typo / case-sensitive: " + ", ".join(zero))

        # ---- Step 3: encode only the selected values
        if selected and st.button("🎭 Encode selected", type="primary"):
            cb = prev_cb if prev_cb else Codebook()

            def fn(text):
                n = 0
                for orig in sorted(selected, key=len, reverse=True):
                    if orig in text:
                        cat = selected[orig]
                        token = cb.token_for(orig, cat, CAT_PREFIX.get(cat, "CUSTX"))
                        n += text.count(orig)
                        text = text.replace(orig, token)
                return text, n

            entries_bytes = None
            if pasted:
                masked, n = fn(pasted)
                st.write(f"✅ {n} replacements")
                st.text_area("Hasil masked — copy dari sini, kasih ke AI", masked,
                             height=200, key="mask_txt_out")
            results = []
            if ups:
                results = _process(ups, fn, "_masked")
                for name, data, n in results:
                    if data is None:
                        st.warning(f"{name}: {n}")
                    else:
                        st.write(f"✅ **{name}** — {n} replacements")

            entries = {o: {"token": t, "category": cb.categories.get(o, "?"),
                           "recommendation": MASK_RECOMMENDATION.get(cb.categories.get(o, ""), "")}
                       for o, t in cb.map.items()}
            map_bytes = json.dumps({"meta": cb.meta, "entries": entries}, indent=2).encode()

            st.divider()
            st.subheader(f"Codebook — {len(cb.map)} unique values")
            st.dataframe([{"Original": o, "Token": t, "Category": cb.categories.get(o, "?")}
                          for o, t in cb.map.items()], use_container_width=True)
            st.error("⚠️ Simpan mapping.json SEKARANG (download atau copy) — itu kunci decode, jangan ikut ke AI.")
            with st.expander("📋 Copy mapping.json sebagai teks"):
                st.code(map_bytes.decode(), language="json")
            c1, c2 = st.columns(2)
            c2.download_button("⬇️ mapping.json saja", map_bytes,
                               "mapping.json", "application/json")
            if results:
                zbuf = _zip_results(results, extra={"mapping.json": map_bytes})
                c1.download_button("⬇️ Masked files + mapping.json (zip)", zbuf,
                                   "masked_bundle.zip", "application/zip", type="primary")
            else:
                c1.download_button("⬇️ mapping.json (primary)", map_bytes,
                                   "mapping_.json", "application/json", type="primary")

# ------------------------------------------------------------------ DECODE
with tab_decode:
    st.subheader("Decode file hasil AI (atau file masked apa pun)")
    st.markdown(
        "Alur: file masked lo kasih ke AI → AI bikin PPT/report berisi token "
        "(`HOSTX001`, `IPX002`, ...) → upload hasilnya di sini **plus mapping.json** "
        "→ semua token dikembalikan ke nilai asli."
    )
    mode = st.radio("Input", ["📁 Upload file", "📋 Paste text"], horizontal=True, key="dec_mode")
    dec_cb = mapping_input("Codebook", "dec_map")

    if mode == "📋 Paste text":
        pasted = st.text_area("Paste output AI yang berisi token (HOSTX001, IPX002, ...)",
                              height=220, key="dec_txt")
        if pasted and dec_cb and st.button("Decode text", type="primary", key="dec_txt_btn"):
            cb = dec_cb
            if True:
                table = decode_table(pasted, cb)
                restored, n = unmask_text(pasted, cb)
                st.write(f"🔓 {n} token direstorasi ({len(table)} unique)")
                if table:
                    st.subheader("Decode summary")
                    st.dataframe(table, use_container_width=True)
                st.text_area("Hasil decoded", restored, height=220, key="dec_txt_out")
                if n == 0:
                    st.info("Tidak ada token ditemukan — cek mapping.json-nya.")

    ups = None
    if mode == "📁 Upload file":
        ups = st.file_uploader("Upload files to decode (pptx/docx/xlsx/csv/...)",
                               type=[e.lstrip(".") for e in SUPPORTED],
                               accept_multiple_files=True, key="dec_up")
    if ups and dec_cb and st.button("Decode", type="primary"):
        cb = dec_cb
        if True:
            results, total = [], 0
            all_rows = {}
            for up in ups:
                ext = os.path.splitext(up.name)[1].lower()
                handler = HANDLERS.get(ext)
                if not handler:
                    st.warning(f"{up.name}: unsupported type {ext}")
                    continue
                in_path = _save_upload(up)
                rows = decode_table(extract_text(in_path), cb)
                out_path = in_path + ".out" + ext
                n = handler(in_path, out_path, lambda t: unmask_text(t, cb))
                with open(out_path, "rb") as f:
                    data = f.read()
                os.unlink(in_path); os.unlink(out_path)
                stem, e = os.path.splitext(up.name)
                name = f"{stem}_restored{e}"
                results.append((name, data, n))
                total += n
                st.write(f"🔓 **{name}** — {n} token direstorasi")
                if rows:
                    st.dataframe(rows, use_container_width=True)
                    for r in rows:
                        key = r["Token"]
                        if key in all_rows:
                            all_rows[key]["Count"] += r["Count"]
                        else:
                            all_rows[key] = dict(r)
                st.download_button(f"⬇️ {name}", data, name, key=f"dl_{name}")
            if len(results) > 1:
                st.divider()
                st.subheader("Decode summary — semua file")
                st.dataframe(sorted(all_rows.values(), key=lambda r: r["Token"]),
                             use_container_width=True)
                st.download_button("⬇️ Download semua (zip)", _zip_results(results),
                                   "restored_bundle.zip", "application/zip", type="primary")
            if total == 0:
                st.info("Tidak ada token ditemukan — cek apakah mapping.json-nya benar "
                        "untuk batch ini, atau AI mengubah format token.")
