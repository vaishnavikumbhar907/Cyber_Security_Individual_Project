# Cyber_Security_Individual_Project

# 🛡️ File Integrity Monitoring (FIM)

## What is this project?
This tool checks whether any files in a folder have been **changed, added, or deleted**.

First it takes a "photo" of your folder when everything is safe. Later, it compares the folder with that photo. If anything is different, it tells you.

## Why is it useful?
Hackers and malware often secretly change files. A normal user may not notice. This tool catches those changes quickly.

## How does it work?
1. **Hashing:** Every file gets a unique 64-character fingerprint (SHA-256 hash). If even one letter in the file changes, the fingerprint changes completely.
2. **Baseline:** All fingerprints are saved in `baseline.json`. This is the trusted "photo".
3. **Check:** The tool calculates the fingerprints again and compares them with the baseline.
4. **Result:**
   - 🔴 **Modified** - file content changed
   - 🟡 **Added** - a new file appeared
   - 🔴 **Deleted** - a file is missing
   - ✅ **OK** - nothing changed
5. **Audit log:** Every change is saved with date and time in `audit_log.csv`.

## Protecting the baseline (HMAC secret key)
A hacker could also edit `baseline.json` to hide their changes. To stop this, you enter a **secret key** (any password you choose, for example `Fim@Cyber#2026!`).

The tool uses the key to "sign" the baseline. If someone edits it, the signature breaks and you see **"BASELINE TAMPERED"**.

Use the same key every time for the same baseline.

## Files in this project
| File | Purpose |
|---|---|
| `app.py` | The website (Streamlit dashboard) |
| `fim_core.py` | The main logic (hashing, comparing, logging) |
| `requirements.txt` | Libraries to install |
| `baseline.json` | Created by the tool - saved fingerprints |
| `audit_log.csv` | Created by the tool - history of changes |

## How to run

**Step 1 - Install libraries** (one time only)
```
pip install -r requirements.txt
```

**Step 2 - Start the website**
```
streamlit run app.py
```
Your browser opens at `http://localhost:8501`.

## How to use the website
1. In the left sidebar, choose a folder (type the path or click **Browse**).
2. Type a secret key.
3. Click **Create / reset baseline**.
4. Change something in the folder (edit, add or delete a file).
5. Open the **Scan** tab and click **Run integrity check**.
6. See the results. The **Hash comparison** tab shows old vs new fingerprints, and the **Audit log** tab shows the history.

## Which folder should I choose?
Use a small test folder with a few files, for example `C:\FIM_Demo`. Do not choose `C:\Windows` or other system folders - they are huge and change all the time.

## Command line option (without website)
```
python fim_core.py init --key MySecret
python fim_core.py check --key MySecret
python fim_core.py watch --key MySecret --interval 5
```
The tool will ask you for the folder. `watch` keeps checking every 5 seconds.

## Demo idea
1. Create a baseline for a test folder.
2. Edit one text file.
3. Run the check and show the before/after hash comparison.
4. Edit `baseline.json` by hand and show the tamper warning.

## Limitations
- A hash shows **that** a file changed, but not **who** changed it.
- Keep `baseline.json` and the logs in a safe place.
- The tool checks only when you click the button (or when using `watch`).

## Tech used
Python, hashlib, pathlib, JSON, CSV, HMAC, Streamlit

Name: Vaishnavi Kumbhar
