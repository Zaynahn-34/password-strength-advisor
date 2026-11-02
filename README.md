# 🔐 Password Strength & Breach Advisor

A Streamlit app that checks how strong a password is, tells you whether it appeared in known data breaches, and gives AI-powered improvement tips using Gemini Flash.

## Features
- Strength score (0-100), entropy and rough crack-time estimate
- Detects common passwords, leetspeak tricks (`P@ssw0rd`), sequences (`abcd`, `qwer`), repeats and years
- Breach check using Have I Been Pwned (k-anonymity)
- AI advice in Roman Urdu + English
- "Habits advisor": describe how you manage passwords and get a fix-it plan

## Privacy
- The password is analysed **locally** inside the app.
- The password is **never sent to Gemini**. Gemini only gets a summary (length, character types, patterns, score).
- Breach check sends only the **first 5 characters of the SHA-1 hash**, never the password.
- Nothing is stored or logged.

## Run locally
```bash
pip install -r requirements.txt
export GEMINI_API_KEY="your_key_here"      # Windows PowerShell: $env:GEMINI_API_KEY="your_key_here"
streamlit run app.py
```
Get a free key from https://aistudio.google.com/apikey

## Deploy on Streamlit Community Cloud
1. Push this repo to GitHub.
2. Go to https://share.streamlit.io and sign in with GitHub.
3. Click **Create app**, choose your repo, branch `main`, main file `app.py`.
4. Open **Advanced settings → Secrets** and add:
   ```toml
   GEMINI_API_KEY = "your_key_here"
   ```
5. Click **Deploy**.

## Files
- `app.py` - the app
- `requirements.txt` - dependencies
- `README.md` - this file

## Tech
Python, Streamlit, Google Gemini Flash (`google-genai`), Have I Been Pwned API.

> Educational project. Do not enter your real important passwords; use a similar-looking test password.
