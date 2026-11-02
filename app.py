"""Password Strength & Breach Advisor
Streamlit UI + Gemini Flash for advice.

PRIVACY DESIGN
- The password is analysed locally inside this app.
- The password itself is NEVER sent to Gemini.
- Gemini only receives a summary (length, character types, patterns found, score).
- Optional breach check uses the Have I Been Pwned "k-anonymity" API:
  only the first 5 characters of the SHA-1 hash are sent, never the password.
"""

import hashlib
import math
import os
import re
import string

import requests
import streamlit as st

try:
    from google import genai
except ImportError:  # app still works without AI advice
    genai = None

MODEL_NAME = "gemini-2.5-flash"

# Small built-in list of very common passwords / words (lowercase).
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "123456789", "qwerty", "abc123",
    "111111", "123123", "admin", "letmein", "welcome", "iloveyou",
    "monkey", "dragon", "football", "login", "passw0rd", "master",
    "sunshine", "princess", "pakistan", "peshawar", "allah", "khan",
    "ali", "ahmed", "bismillah", "000000", "1q2w3e4r", "qwerty123",
    "password1", "admin123", "changeme", "test", "user", "guest",
}

KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]

LEET_MAP = str.maketrans("@4$!10357", "aasiloest")


# ----------------------------------------------------------------------
# Local analysis (no network, no AI)
# ----------------------------------------------------------------------
def char_pool_size(password: str) -> int:
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"\d", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32
    return pool


def has_sequence(password: str, min_len: int = 4) -> bool:
    """Detect runs like abcd, 1234, dcba, 4321 or keyboard walks like qwer."""
    p = password.lower()
    if len(p) < min_len:
        return False
    alphabets = [string.ascii_lowercase, string.digits] + KEYBOARD_ROWS
    for seq in alphabets:
        for s in (seq, seq[::-1]):
            for i in range(len(s) - min_len + 1):
                if s[i:i + min_len] in p:
                    return True
    return False


def has_repeats(password: str, min_len: int = 3) -> bool:
    """Detect aaa, 1111 or repeated chunks like abcabc."""
    if re.search(r"(.)\1{%d,}" % (min_len - 1), password):
        return True
    return bool(re.search(r"(.{2,})\1", password))


def has_year(password: str) -> bool:
    return bool(re.search(r"(19\d{2}|20\d{2})", password))


def is_common(password: str) -> bool:
    p = password.lower()
    deleet = p.translate(LEET_MAP)
    stripped = re.sub(r"[^a-z]", "", deleet)
    base = re.sub(r"\d+$", "", p)
    candidates = {p, deleet, stripped, base}
    return any(c in COMMON_PASSWORDS for c in candidates if c)


def analyse_password(password: str) -> dict:
    """Return a dict of metrics, issues and a 0-100 score."""
    length = len(password)
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))
    pool = char_pool_size(password)
    entropy = length * math.log2(pool) if pool and length else 0.0

    issues = []
    common = is_common(password)
    seq = has_sequence(password)
    rep = has_repeats(password)
    year = has_year(password)
    unique_ratio = len(set(password)) / length if length else 0

    if length < 8:
        issues.append("Bohat chhota (8 se kam characters)")
    elif length < 12:
        issues.append("12+ characters behtar hain")
    if not has_lower:
        issues.append("Lowercase letters nahi hain")
    if not has_upper:
        issues.append("Uppercase letters nahi hain")
    if not has_digit:
        issues.append("Numbers nahi hain")
    if not has_symbol:
        issues.append("Symbols nahi hain")
    if common:
        issues.append("Common / guessable password ya uska variation")
    if seq:
        issues.append("Sequence ya keyboard pattern mila (abcd, 1234, qwer)")
    if rep:
        issues.append("Repeated characters ya chunks mile")
    if year:
        issues.append("Year (jaise 1999 ya 2024) mili, ye guess karna aasan hota hai")
    if length and unique_ratio < 0.5:
        issues.append("Bohat kam unique characters")

    # Score: based on entropy, then penalties.
    score = min(100.0, entropy / 80.0 * 100.0)
    if common:
        score = min(score, 10)
    if seq:
        score -= 15
    if rep:
        score -= 15
    if year:
        score -= 8
    if length and unique_ratio < 0.5:
        score -= 10
    if length < 8:
        score = min(score, 25)
    score = int(max(0, min(100, round(score))))

    if not password:
        label = "-"
    elif score < 25:
        label = "Bohat kamzor"
    elif score < 50:
        label = "Kamzor"
    elif score < 70:
        label = "Theek-thaak"
    elif score < 85:
        label = "Strong"
    else:
        label = "Bohat strong"

    return {
        "length": length,
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_digit": has_digit,
        "has_symbol": has_symbol,
        "entropy_bits": round(entropy, 1),
        "common": common,
        "sequence": seq,
        "repeats": rep,
        "year": year,
        "issues": issues,
        "score": score,
        "label": label,
    }


def crack_time_text(entropy_bits: float) -> str:
    """Rough offline-attack estimate at 10 billion guesses/second."""
    if entropy_bits <= 0:
        return "-"
    seconds = (2 ** entropy_bits) / 2 / 1e10
    units = [
        ("saal", 31_536_000),
        ("din", 86_400),
        ("ghante", 3600),
        ("minute", 60),
    ]
    if seconds < 1:
        return "1 second se kam"
    if seconds > 31_536_000 * 1e9:
        return "arabon saal se zyada"
    for name, size in units:
        if seconds >= size:
            value = seconds / size
            return f"lagbhag {value:,.0f} {name}"
    return f"lagbhag {seconds:,.0f} seconds"


# ----------------------------------------------------------------------
# Breach check (Have I Been Pwned, k-anonymity)
# ----------------------------------------------------------------------
def check_breach(password: str):
    """Return number of times seen in breaches, 0 if not found, None on error."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()  # noqa: S324
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        resp = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"Add-Padding": "true"},
            timeout=8,
        )
        resp.raise_for_status()
    except requests.RequestException:
        return None
    for line in resp.text.splitlines():
        parts = line.strip().split(":")
        if len(parts) == 2 and parts[0] == suffix:
            return int(parts[1])
    return 0


# ----------------------------------------------------------------------
# Gemini advice
# ----------------------------------------------------------------------
def get_api_key():
    try:
        key = st.secrets.get("GEMINI_API_KEY")
        if key:
            return key
    except Exception:
        pass
    return os.getenv("GEMINI_API_KEY")


def build_summary_prompt(metrics: dict, breach_count) -> str:
    breach_text = "not checked"
    if breach_count is not None:
        breach_text = (
            "not found in known breaches" if breach_count == 0
            else f"found in known breaches {breach_count} times"
        )
    return f"""You are a friendly cyber security advisor.
A user checked a password. You are NOT given the password, only this summary:
- length: {metrics['length']}
- lowercase: {metrics['has_lower']}, uppercase: {metrics['has_upper']}, digits: {metrics['has_digit']}, symbols: {metrics['has_symbol']}
- estimated entropy: {metrics['entropy_bits']} bits
- common/guessable: {metrics['common']}
- sequence/keyboard pattern: {metrics['sequence']}
- repeats: {metrics['repeats']}
- contains a year: {metrics['year']}
- score: {metrics['score']}/100 ({metrics['label']})
- breach status: {breach_text}

Write in simple Roman Urdu mixed with English (the way a Pakistani student would text).
Give: 1) a short verdict, 2) the top 3 specific improvements, 3) one tip about
passphrases and password managers, 4) a reminder to use 2FA. Keep it under 180 words.
Never ask for the password and never guess it."""


def build_habits_prompt(habits: str) -> str:
    return f"""You are a friendly cyber security advisor.
A user describes how they create and manage passwords (they were told NOT to share real passwords):

\"\"\"{habits[:2000]}\"\"\"

Write in simple Roman Urdu mixed with English.
Give: 1) what they are doing wrong, 2) what they are doing right, 3) a simple
step-by-step plan to fix their habits (password manager, unique passwords, 2FA,
passphrases), 4) a final short checklist. Keep it under 250 words.
If the text contains what looks like a real password, tell them to change it
and do not repeat it."""


def ask_gemini(prompt: str) -> str:
    if genai is None:
        return "google-genai install nahi hai. requirements.txt se install karein."
    api_key = get_api_key()
    if not api_key:
        return "GEMINI_API_KEY set nahi hai. README mein setup steps dekhein."
    try:
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(model=MODEL_NAME, contents=prompt)
        return response.text or "AI se jawab nahi aaya, dobara try karein."
    except Exception as exc:  # network, quota, invalid key, etc.
        return f"AI advice nahi mil saki: {exc}"


# ----------------------------------------------------------------------
# UI
# ----------------------------------------------------------------------
def render_password_tab():
    st.subheader("Password check karein")
    st.caption(
        "Aapka password AI ko kabhi nahi bheja jata. Analysis isi app ke andar hota hai. "
        "Phir bhi, apna real important password enter na karein, similar pattern wala test password use karein."
    )
    password = st.text_input("Password", type="password", key="pw_input")
    check_breach_opt = st.checkbox(
        "Breach database check karein (sirf hash ke pehle 5 characters bheje jate hain)",
        value=True,
    )
    use_ai = st.checkbox("AI advice chahiye (Gemini)", value=True)

    if not st.button("Analyse karein", type="primary", key="pw_btn"):
        return
    if not password:
        st.warning("Pehle password likhein.")
        return

    metrics = analyse_password(password)
    breach_count = check_breach(password) if check_breach_opt else None

    col1, col2, col3 = st.columns(3)
    col1.metric("Score", f"{metrics['score']}/100")
    col2.metric("Rating", metrics["label"])
    col3.metric("Entropy", f"{metrics['entropy_bits']} bits")
    st.progress(metrics["score"] / 100)
    st.write(f"**Estimated crack time (offline attack):** {crack_time_text(metrics['entropy_bits'])}")

    if check_breach_opt:
        if breach_count is None:
            st.info("Breach check abhi nahi ho saka (internet ya API issue).")
        elif breach_count == 0:
            st.success("Ye password known breaches mein nahi mila.")
        else:
            st.error(
                f"Ye password known breaches mein {breach_count:,} baar mila hai. "
                "Isay kabhi use na karein."
            )

    if metrics["issues"]:
        st.markdown("**Masail:**")
        for item in metrics["issues"]:
            st.write(f"- {item}")
    else:
        st.success("Koi bada masla nahi mila.")

    if use_ai:
        with st.spinner("AI advice tayar ho rahi hai..."):
            advice = ask_gemini(build_summary_prompt(metrics, breach_count))
        st.markdown("### AI Advice")
        st.write(advice)


def render_habits_tab():
    st.subheader("Apni password habits batayein")
    st.caption("Yahan real password mat likhein. Sirf apni habits likhein.")
    habits = st.text_area(
        "Misal: Main har site pe same password use karta hoon, naam + birth year lagata hoon...",
        height=160,
        key="habits_input",
    )
    if st.button("Advice lein", type="primary", key="habits_btn"):
        if len(habits.strip()) < 15:
            st.warning("Thora tafseel se likhein (kam az kam ek do jumlay).")
            return
        with st.spinner("AI advice tayar ho rahi hai..."):
            advice = ask_gemini(build_habits_prompt(habits))
        st.markdown("### AI Advice")
        st.write(advice)


def main():
    st.set_page_config(page_title="Password Strength Advisor", page_icon="🔐")
    st.title("🔐 Password Strength & Breach Advisor")
    st.write("Password ki strength check karein, breach status dekhein aur AI se improvement tips lein.")
    tab1, tab2 = st.tabs(["Password check", "Habits advisor"])
    with tab1:
        render_password_tab()
    with tab2:
        render_habits_tab()
    st.divider()
    st.caption("Educational project. Koi password store ya log nahi kiya jata.")


if __name__ == "__main__":
    main()
