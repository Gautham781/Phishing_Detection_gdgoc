# =========================
# PHISHING DETECTION SYSTEM
# Phase 2 + Phase 3 + Final Scoring
# =========================

import os
import re
import json
import base64
import email
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup
import subprocess

# =========================
# CONFIGURATION
# =========================

SAMPLES_DIR = "samples"       # fallback local .eml files
OUTPUT_DIR = "output"

MAX_SCORE = 100

# Phase 2 weights
SENDER_SPOOFING_POINTS = 20
AUTH_FAILURE_POINTS = 30
KEYWORD_POINTS = 15
x
# Phase 3 weights
SUSPICIOUS_LINK_POINTS = 20
DANGEROUS_ATTACHMENT_POINTS = 20

SUSPICIOUS_KEYWORDS = [
    "urgent",
    "account suspended",
    "verify your account",
    "password expired",
    "click here"
]

DANGEROUS_EXTENSIONS = [".exe", ".zip", ".js", ".iso"]

# =========================
# PHASE 2 – EMAIL ANALYSIS
# =========================

def extract_headers(msg):
    return dict(msg.items())

def extract_body(msg):
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                body += part.get_content()
    else:
        body = msg.get_content()
    return body

def phase2_analysis(msg):
    headers = extract_headers(msg)
    body = extract_body(msg)
    subject = headers.get("Subject", "").lower()

    score = 0
    evidence = []

    # Sender spoofing
    from_header = headers.get("From", "")
    return_path = headers.get("Return-Path", "")
    if from_header and return_path and from_header not in return_path:
        score += SENDER_SPOOFING_POINTS
        evidence.append("Sender spoofing detected (domain mismatch)")

    # SPF / DKIM failure
    auth_results = headers.get("Authentication-Results", "").lower()
    if "spf=fail" in auth_results or "dkim=fail" in auth_results:
        score += AUTH_FAILURE_POINTS
        evidence.append("SPF/DKIM authentication failed")

    # Keyword detection
    found_keywords = [k for k in SUSPICIOUS_KEYWORDS if k in subject or k in body.lower()]
    if found_keywords:
        score += KEYWORD_POINTS
        evidence.append(f"Suspicious keywords found: {found_keywords}")

    return min(score, MAX_SCORE), evidence

# =========================
# PHASE 3 – FORENSICS
# =========================

def extract_links(html):
    soup = BeautifulSoup(html, "html.parser")
    return [a.get("href") for a in soup.find_all("a", href=True)]

def trace_url_nmap(url):
    try:
        result = subprocess.run(
            ["nmap", "--script", "http-title", url],
            capture_output=True,
            text=True,
            timeout=10
        )
        return "Suspicious" if result.returncode == 0 else "Unknown"
    except Exception:
        return "Unknown"

def phase3_analysis(msg):
    body = extract_body(msg)
    score = 0
    evidence = []

    # Link analysis
    links = extract_links(body)
    if links:
        score += SUSPICIOUS_LINK_POINTS
        evidence.append("Suspicious links detected")

    # Attachment analysis
    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            for ext in DANGEROUS_EXTENSIONS:
                if filename.lower().endswith(ext):
                    score += DANGEROUS_ATTACHMENT_POINTS
                    evidence.append(f"Suspicious attachment: {filename}")

    return min(score, MAX_SCORE), evidence

# =========================
# FINAL RISK SCORING
# =========================

def final_risk_score(phase2, phase3):
    base = (0.65 * phase2) + (0.35 * phase3)
    amplifier = 0

    if phase2 >= 80 and phase3 >= 20:
        amplifier += 10
    if phase2 >= 90:
        amplifier += 5
    if phase3 >= 40:
        amplifier += 5

    return min(int(base + amplifier), MAX_SCORE)

# =========================
# MAIN PIPELINE
# =========================

def analyze_eml(file_path):
    with open(file_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    phase2_score, phase2_evidence = phase2_analysis(msg)
    phase3_score, phase3_evidence = phase3_analysis(msg)
    final_score = final_risk_score(phase2_score, phase3_score)

    return {
        "email_file": os.path.basename(file_path),
        "phase_2_score": phase2_score,
        "phase_3_score": phase3_score,
        "final_risk_score": f"{final_score}/100",
        "evidence": phase2_evidence + phase3_evidence
    }

def run():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    for file in os.listdir(SAMPLES_DIR):
        if file.endswith(".eml"):
            report = analyze_eml(os.path.join(SAMPLES_DIR, file))
            out_file = file.replace(".eml", ".json")

            with open(os.path.join(OUTPUT_DIR, out_file), "w") as f:
                json.dump(report, f, indent=4)

            print(f"Processed: {file}")

if __name__ == "__main__":
    run()
