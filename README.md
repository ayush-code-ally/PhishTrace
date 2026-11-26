# PhishTrace: Account Takeover (ATO) Security Gateway

## Run Instructions (Local Floci Emulator)
1. **Start the Emulator:** Open a WSL terminal and run `floci gcp start` (Port 4588).
2. **Setup Environment:** In Git Bash, run `source venv/Scripts/activate`.
3. **Provision Database:** Run `python seed.py` to create PBKDF2 hashed users and the Pub/Sub topic.
4. **Start the Gateway:** Run `uvicorn main:app --port 8000`.
5. **Start SOC Monitor:** In a second Git Bash terminal, run `python alert_listener.py`.
6. **Access Portal:** Open `http://localhost:8000/` in a web browser.