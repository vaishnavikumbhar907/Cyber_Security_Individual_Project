"""Streamlit dashboard for the File Integrity Monitor.  Run: streamlit run app.py"""
import os
import pandas as pd
import streamlit as st
import fim_core as fim

st.set_page_config(page_title="File Integrity Monitor", page_icon="🛡️", layout="wide")
st.title("🛡️ File Integrity Monitor")
st.caption("Detect whether monitored files have changed since a trusted baseline (SHA-256).")

with st.sidebar:
    st.header("Setup")
    if "folder" not in st.session_state:
        st.session_state["folder"] = ""

    def browse():
        # runs BEFORE the text box is drawn, so changing its value is allowed
        picked = fim.pick_folder()
        if picked:
            st.session_state["folder"] = picked
        else:
            st.session_state["browse_failed"] = True

    st.text_input("Folder to monitor", key="folder",
                  placeholder=r"C:\Users\you\Documents\test")
    st.button("📂 Browse for folder...", on_click=browse, use_container_width=True)
    if st.session_state.pop("browse_failed", False):
        st.warning("No folder chosen (or no GUI available) - type the path instead.")
    folder = st.session_state["folder"].strip().strip('"')
    if folder and os.path.isdir(folder):
        st.caption(f"✅ {len(fim.scan_folder(folder))} files found")
    elif folder:
        st.caption("❌ Folder does not exist")
    key = st.text_input("Baseline secret key (HMAC)", type="password",
                        help="Protects baseline.json from silent tampering")
    if st.button("📌 Create / reset baseline", use_container_width=True):
        if folder and os.path.isdir(folder):
            d = fim.save_baseline(folder, key=key)
            st.success(f"Baseline saved for {len(d['files'])} files")
        else:
            st.error("Please choose a valid folder first")
    st.info("A hash shows *that* a file changed, not *who* changed it. "
            "Keep the baseline and logs on protected storage.")

tab1, tab2, tab3 = st.tabs(["🔍 Scan", "📊 Hash comparison", "📜 Audit log"])

with tab1:
    if st.button("Run integrity check", type="primary"):
        if not (folder and os.path.isdir(folder)):
            st.warning("Choose a valid folder first.")
        elif not os.path.exists(fim.BASELINE_FILE):
            st.warning("Create a baseline first.")
        elif fim.load_baseline(fim.BASELINE_FILE)["folder"] != os.path.abspath(folder):
            st.warning("The baseline was made for a different folder. Click 'Create / reset baseline'.")
        else:
            try:
                report, base, now = fim.check(folder, key=key)
                st.session_state["result"] = (report, base, now)
            except ValueError as e:
                st.error(str(e))
    if "result" in st.session_state:
        report, base, now = st.session_state["result"]
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Modified", len(report["modified"]))
        c2.metric("Added", len(report["added"]))
        c3.metric("Deleted", len(report["deleted"]))
        c4.metric("Unchanged", len(report["unchanged"]))
        if not (report["modified"] or report["added"] or report["deleted"]):
            st.success("✅ All files match the baseline.")
        for f in report["modified"]: st.error(f"MODIFIED: {f}")
        for f in report["added"]: st.warning(f"ADDED: {f}")
        for f in report["deleted"]: st.error(f"DELETED: {f}")

with tab2:
    if "result" in st.session_state:
        report, base, now = st.session_state["result"]
        rows = []
        for f in sorted(set(base) | set(now)):
            status = ("MODIFIED" if f in report["modified"] else "ADDED" if f in report["added"]
                      else "DELETED" if f in report["deleted"] else "OK")
            rows.append({"File": f, "Status": status,
                         "Baseline hash": base.get(f, {}).get("sha256", "—"),
                         "Current hash": now.get(f, {}).get("sha256", "—")})
        st.dataframe(pd.DataFrame(rows), use_container_width=True)
    else:
        st.write("Run a scan to see before/after hashes.")

with tab3:
    if os.path.exists(fim.LOG_FILE):
        df = pd.read_csv(fim.LOG_FILE).iloc[::-1]
        st.dataframe(df, use_container_width=True)
        st.download_button("Download log (CSV)", df.to_csv(index=False), "audit_log.csv")
    else:
        st.write("No events logged yet.")