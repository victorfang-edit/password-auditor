"""Password strength auditor.

usage:
  python audit.py                  (prompts without echoing: nothing lands in shell history)
  python audit.py --hibp           (also check the Have I Been Pwned breach corpus, privately)
  python audit.py --file list.txt  (audit one password per line, e.g. a policy test set)
"""
import argparse
import getpass
import hashlib
import math
import os
import re
import ssl
import sys
import urllib.request

RED, YEL, GRN, DIM, B, R = "\033[31m", "\033[33m", "\033[32m", "\033[2m", "\033[1m", "\033[0m"
if not (sys.stdout.isatty() or os.environ.get("FORCE_COLOR")):
    RED = YEL = GRN = DIM = B = R = ""

# a short sample of the most common passwords from public breach statistics
COMMON = set("""123456 password 12345678 qwerty 123456789 12345 1234 111111 1234567 dragon 123123 baseball abc123
football monkey letmein 696969 shadow master 666666 qwertyuiop 123321 mustang 1234567890 michael 654321 superman
1qaz2wsx 7777777 121212 000000 qazwsx 123qwe killer trustno1 jordan jennifer zxcvbnm asdfgh hunter buster soccer
harley batman andrew tigger sunshine iloveyou 2000 charlie robert thomas hockey ranger daniel starwars klaster
112233 george computer michelle jessica pepper 1111 zxcvbn 555555 11111111 131313 freedom 777777 pass maggie
159753 aaaaaa ginger princess joshua cheese amanda summer love ashley nicole chelsea biteme matthew access yankees
987654321 dallas austin thunder taylor matrix admin welcome login passw0rd password1 password123 welcome1""".split())
KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]
LEET = str.maketrans("@4310$5!7", "aaeiossit")


def charset_size(pw):
    return sum(n for pattern, n in ((r"[a-z]", 26), (r"[A-Z]", 26), (r"\d", 10), (r"[^a-zA-Z\d]", 33)) if re.search(pattern, pw))


def findings(pw):
    """(penalty in bits, message) for each weakness found."""
    out, low = [], pw.lower()
    # strip trailing digits/symbols first, then undo l33t swaps: 'P@ssw0rd!' -> 'password', 'Summer2024' -> 'summer'
    base = re.sub(r"[\d!@#$%^&*]+$", "", low).translate(LEET)
    if low in COMMON or base in COMMON:
        out.append((999, "on the list of most common passwords"))
    if len(pw) < 12:
        out.append((0, f"only {len(pw)} characters (12+ recommended, NIST SP 800-63B)"))
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - 3):
            if row[i:i + 4] in low or row[i:i + 4][::-1] in low:
                out.append((15, f"keyboard pattern '{row[i:i + 4]}'"))
                break
    if re.search(r"(.)\1{2,}", pw):
        out.append((10, "repeated characters"))
    if re.search(r"(19|20)\d\d", pw):
        out.append((10, "contains a year (often a birthday or the current year)"))
    if base != low and base in COMMON:
        out.append((0, "common word disguised with l33t swaps / trailing digits: attackers try these first"))
    return out


def score(pw):
    raw_bits = len(pw) * math.log2(max(charset_size(pw), 1))
    issues = findings(pw)
    bits = 0 if any(p == 999 for p, _ in issues) else max(raw_bits - sum(p for p, _ in issues), 0)
    if len(pw) < 12:
        bits = min(bits, 59)  # policy: short passwords cap at FAIR no matter how random
    rating = ("VERY WEAK", RED) if bits < 28 else ("WEAK", RED) if bits < 45 else ("FAIR", YEL) if bits < 60 else ("STRONG", GRN)
    return bits, rating, issues


def pwned_count(pw):
    """k-anonymity: only the first 5 hex chars of the SHA-1 leave this machine; the match happens locally."""
    digest = hashlib.sha1(pw.encode()).hexdigest().upper()
    req = urllib.request.Request(f"https://api.pwnedpasswords.com/range/{digest[:5]}", headers={"Add-Padding": "true"})
    try:
        import certifi  # python.org builds on macOS ship without CA certs
        ctx = ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
        for line in resp.read().decode().splitlines():
            suffix, count = line.split(":")
            if suffix == digest[5:]:
                return int(count)
    return 0


def audit(pw, label, hibp):
    bits, (rating, color), issues = score(pw)
    print(f"{B}{label}{R}  {color}{rating}{R}  {DIM}≈{bits:.0f} bits of entropy{R}")
    for _, msg in issues:
        print(f"   {YEL}!{R} {msg}")
    if hibp:
        try:
            n = pwned_count(pw)
            print(f"   {RED}✘ seen {n:,} times in data breaches: never use it{R}" if n else f"   {GRN}✔ not found in known breaches{R}")
        except OSError as e:
            print(f"   {DIM}breach check unavailable ({e}){R}")
    if not issues and bits >= 60:
        print(f"   {GRN}✔ no weaknesses found{R}")


def mask(pw):
    return pw[0] + "*" * (len(pw) - 2) + pw[-1] if len(pw) > 2 else "**"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--hibp", action="store_true")
    ap.add_argument("--file")
    ap.add_argument("--show", action="store_true", help="print passwords in clear (demo lists only)")
    a = ap.parse_args()
    if a.file:
        with open(a.file) as f:
            for pw in (line.rstrip("\n") for line in f if line.strip()):
                audit(pw, pw if a.show else mask(pw), a.hibp)
    else:
        audit(getpass.getpass("password (hidden): "), "your password", a.hibp)


if __name__ == "__main__":
    main()
