"""
Password Policy Auditor

Scores passwords, explains the weaknesses an attacker would exploit, and shows how much
the choice of hashing algorithm changes the time it would take to guess them.

It is a defensive tool: it audits a list YOU own (e.g. a test set, or your own policy
examples) and writes a short controls memo, like the one the Goldman Sachs Forage
engineering simulation asks for.

Usage:
    python auditor.py check "Summer2024!"
    python auditor.py audit sample_passwords.txt --memo memo.md
    python auditor.py hashing
"""

from __future__ import annotations

import argparse
import hashlib
import math
import os
import re
import string
import time
from dataclasses import dataclass, field

# A small built-in list of very common passwords and base words. Real systems check
# against much bigger breach lists (for example via the k-anonymity Pwned Passwords API).
COMMON = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty", "abc123", "111111",
    "password1", "iloveyou", "1234567", "123123", "admin", "welcome", "letmein", "monkey",
    "dragon", "football", "sunshine", "princess", "qwerty123", "000000", "trustno1",
    "master", "login", "starwars", "shadow", "superman", "passw0rd", "hello", "freedom",
    "whatever", "charlie", "secret", "summer", "winter", "spring", "autumn", "london",
    "birmingham", "goldman", "liverpool", "arsenal", "chelsea",
}
KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})

# Rough guesses per second for ONE modern GPU. Orders of magnitude are what matter here.
GUESSES_PER_SECOND = {
    "md5 (unsalted, fast)": 60e9,
    "sha256 (unsalted, fast)": 20e9,
    "pbkdf2-sha256, 600k iterations": 3e3,
    "bcrypt, cost 12": 1.5e3,
}


@dataclass
class Report:
    password: str
    length: int
    pool: int
    entropy_bits: float
    score: int
    issues: list[str] = field(default_factory=list)

    @property
    def rating(self) -> str:
        return ["Very weak", "Weak", "Fair", "Strong", "Very strong"][min(self.score // 20, 4)]

    @property
    def masked(self) -> str:
        if len(self.password) <= 2:
            return "*" * len(self.password)
        return self.password[0] + "*" * (len(self.password) - 2) + self.password[-1]


def char_pool(pw: str) -> int:
    pool = 0
    if any(c in string.ascii_lowercase for c in pw):
        pool += 26
    if any(c in string.ascii_uppercase for c in pw):
        pool += 26
    if any(c in string.digits for c in pw):
        pool += 10
    if any(c in string.punctuation or c == " " for c in pw):
        pool += 33
    if any(ord(c) > 127 for c in pw):
        pool += 100
    return pool


def has_sequence(pw: str, run: int = 4) -> bool:
    """True if pw contains a keyboard or alphabet run like 'qwer', 'asdf', '1234' or 'abcd'."""
    low = pw.lower()
    sources = KEYBOARD_ROWS + [string.ascii_lowercase]
    for src in sources:
        for seq in (src, src[::-1]):
            for i in range(len(seq) - run + 1):
                if seq[i:i + run] in low:
                    return True
    return False


def analyse(pw: str) -> Report:
    issues: list[str] = []
    pool = char_pool(pw)
    entropy = len(pw) * math.log2(pool) if pool else 0.0

    normalised = re.sub(r"[^a-z]", "", pw.lower().translate(LEET))
    stripped = re.sub(r"[\d\W_]+$", "", pw.lower())  # "Summer2024!" -> "summer"

    if pw.lower() in COMMON:
        issues.append("Is on the common-password list: guessed in the first second of any attack")
        entropy = min(entropy, 10)
    elif stripped in COMMON or normalised in COMMON:
        issues.append("Is a common word with numbers/symbols bolted on or swapped in (p@ssw0rd style)")
        entropy = min(entropy, 25)

    if len(pw) < 12:
        issues.append(f"Only {len(pw)} characters; current NCSC/NIST guidance favours longer passphrases")
    if re.search(r"(.)\1\1", pw):
        issues.append("Repeats the same character 3+ times")
        entropy -= 8
    if has_sequence(pw):
        issues.append("Contains a keyboard or alphabet sequence (qwer, 1234, abcd)")
        entropy -= 10
    if re.search(r"(19|20)\d{2}", pw):
        issues.append("Contains a year, often a birthday or the current year")
        entropy -= 7
    if pool and pool <= 26:
        issues.append("Uses only one type of character")

    entropy = max(entropy, 0.0)
    score = int(max(0, min(100, entropy * 1.25)))
    return Report(pw, len(pw), pool, round(entropy, 1), score, issues)


def human_time(seconds: float) -> str:
    if seconds < 1:
        return "instantly"
    for unit, size in [("years", 31_557_600), ("days", 86_400), ("hours", 3_600), ("minutes", 60)]:
        if seconds >= size:
            value = seconds / size
            if round(value) == 1:
                unit = unit[:-1]
            if unit == "years" and value > 1e6:
                return "over a million years"
            return f"{value:,.0f} {unit}"
    return f"{seconds:,.0f} seconds"


def crack_times(entropy_bits: float) -> dict[str, str]:
    """Average time to guess = half the search space / guesses per second."""
    guesses = 2 ** entropy_bits / 2
    return {algo: human_time(guesses / rate) for algo, rate in GUESSES_PER_SECOND.items()}


def benchmark_hashing(password: str = "correct horse battery staple") -> list[tuple[str, float]]:
    """Measure how long ONE hash takes on this machine. Slow is good for password storage."""
    salt = os.urandom(16)
    tests = {
        "md5": lambda: hashlib.md5(password.encode()).hexdigest(),
        "sha256": lambda: hashlib.sha256(password.encode()).hexdigest(),
        "pbkdf2-sha256 (600k)": lambda: hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000),
        "scrypt (n=2^14)": lambda: hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1),
    }
    results = []
    for name, fn in tests.items():
        start = time.perf_counter()
        fn()
        results.append((name, (time.perf_counter() - start) * 1000))
    return results


def audit(passwords: list[str]) -> dict:
    reports = [analyse(p) for p in passwords if p]
    counts: dict[str, int] = {}
    for r in reports:
        counts[r.rating] = counts.get(r.rating, 0) + 1
    issue_counts: dict[str, int] = {}
    for r in reports:
        for issue in r.issues:
            key = "Shorter than 12 characters" if issue.startswith("Only ") else issue.split(":")[0]
            issue_counts[key] = issue_counts.get(key, 0) + 1
    return {
        "total": len(reports),
        "ratings": counts,
        "issues": sorted(issue_counts.items(), key=lambda kv: -kv[1]),
        "reports": reports,
        "median_entropy": sorted(r.entropy_bits for r in reports)[len(reports) // 2] if reports else 0,
    }


def memo(result: dict) -> str:
    weak = sum(v for k, v in result["ratings"].items() if k in ("Very weak", "Weak"))
    pct = 100 * weak / result["total"] if result["total"] else 0
    lines = [
        "# Password controls review",
        "",
        f"**Finding:** {weak} of {result['total']} passwords ({pct:.0f}%) are weak or very weak. "
        f"Median strength is {result['median_entropy']} bits.",
        "",
        "## Most common weaknesses",
        "",
        "| Weakness | Passwords |",
        "| --- | --- |",
    ]
    lines += [f"| {k} | {v} |" for k, v in result["issues"]]
    lines += [
        "",
        "## Recommended controls",
        "",
        "1. Store passwords with a slow, salted algorithm (bcrypt, scrypt or Argon2), never MD5 or plain SHA.",
        "2. Set a 12-character minimum and allow long passphrases; drop forced complexity rules that push people to `Password1!`.",
        "3. Block known-breached and common passwords at sign-up (k-anonymity breach check).",
        "4. Require multi-factor authentication for every account with access to client data.",
        "5. Rate-limit and alert on repeated failed logins.",
        "",
        "## Ratings",
        "",
        "| Rating | Count |",
        "| --- | --- |",
    ]
    order = ["Very weak", "Weak", "Fair", "Strong", "Very strong"]
    lines += [f"| {k} | {result['ratings'].get(k, 0)} |" for k in order]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Password policy auditor")
    sub = parser.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="analyse one password")
    c.add_argument("password")
    a = sub.add_parser("audit", help="audit a file with one password per line")
    a.add_argument("file")
    a.add_argument("--memo", help="write a markdown controls memo to this path")
    sub.add_parser("hashing", help="benchmark hash speeds on this machine")
    args = parser.parse_args()

    if args.cmd == "check":
        r = analyse(args.password)
        print(f"{r.masked}: {r.rating} ({r.score}/100, ~{r.entropy_bits} bits)")
        for issue in r.issues:
            print("  -", issue)
        print("Average time to guess, by how the password is stored:")
        for algo, t in crack_times(r.entropy_bits).items():
            print(f"  {algo:<34} {t}")
    elif args.cmd == "audit":
        with open(args.file, encoding="utf-8") as f:
            result = audit([line.rstrip("\n") for line in f])
        print(f"Audited {result['total']} passwords: {result['ratings']}")
        for k, v in result["issues"]:
            print(f"  {v:>3}  {k}")
        if args.memo:
            with open(args.memo, "w", encoding="utf-8") as f:
                f.write(memo(result))
            print(f"Memo written to {args.memo}")
    else:
        for name, ms in benchmark_hashing():
            print(f"{name:<22} {ms:10.3f} ms per hash")


if __name__ == "__main__":
    main()
