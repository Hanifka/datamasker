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

from datamask import (
    Codebook, DETECTORS, HANDLERS, MASK_RECOMMENDATION,
    extract_text, find_all, mask_text, unmask_text,
)

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
