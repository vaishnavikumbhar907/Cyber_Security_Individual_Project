# File Integrity Monitoring (FIM)

Detects modified, added and deleted files against a trusted SHA-256 baseline.

## Setup
    pip install -r requirements.txt

## Run the dashboard
    streamlit run app.py

## Or use the CLI
    python fim_core.py init sample_folder --key MySecret
    python fim_core.py check sample_folder --key MySecret
    python fim_core.py watch sample_folder --key MySecret --interval 5

## Demo script (matches the slide)
1. Create baseline for `sample_folder`.
2. Edit `sample_folder/notes.txt`, add a new file, delete `config.ini`.
3. Run the integrity check -> show MODIFIED / ADDED / DELETED and the
   before/after hash table; open the Audit log tab.
4. Bonus: edit `baseline.json` by hand -> the HMAC check reports tampering.

## Design notes
- Files are hashed in 64 KB chunks (handles large files).
- Baseline is HMAC-signed with a secret key so tampering is detectable.
- Audit log (audit_log.csv) is append-only with timestamps.
- Limitation: a hash proves a change, not who made it. Pair with OS audit logs.
