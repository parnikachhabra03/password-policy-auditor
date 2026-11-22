# Password Policy Auditor

A Python command-line tool that scores passwords, explains the weaknesses an attacker would use, shows how much the **storage algorithm** changes the time to crack them, and writes a short **controls memo** for a manager.

**Why I built it:** after the Goldman Sachs Engineering job simulation on Forage (auditing a leaked password database and recommending controls), I wanted to automate the analysis and turn it into a repeatable audit. Guarding against cyber threats is one of the areas Goldman lists for its Engineering division.

> Defensive use only. It audits a list you own (the sample here is made up) and never shows a full password in its output.

## What it does

| Command | Output |
| --- | --- |
| `python auditor.py check "Summer2024!"` | Rating, estimated strength in bits, each weakness, average time to guess under MD5 vs bcrypt |
| `python auditor.py audit sample_passwords.txt --memo memo.md` | Weakness counts across the file + a markdown controls memo |
| `python auditor.py hashing` | Measures how long MD5, SHA-256, PBKDF2 and scrypt take on your machine |
| `python -m unittest discover -s tests` | 9 unit tests |

Standard library only (Python 3.10+).

## Sample results (20 made-up passwords)

- 13 of 20 (65%) rated weak or very weak; median strength 25 bits.
- Most common problem: shorter than 12 characters (16 of 20), then common words with numbers or symbols bolted on, like `Summer2024!` (6).
- On one laptop, one MD5 hash took about 0.01 ms and one PBKDF2 hash (600,000 iterations) about 73 ms: roughly **7,000x slower**, which is the point. Re-run `hashing` on your machine and put your own numbers here.

## How it works

1. **Character pool and entropy.** Length x log2(pool size), where the pool is 26 for lowercase, +26 uppercase, +10 digits, +33 symbols.
2. **Penalties** for what attackers actually try first: common-password lists, "leetspeak" swaps (`P@ssw0rd` -> `password`), years, keyboard runs (`qwer`, `1234`), repeated characters.
3. **Time to guess** = half the search space / guesses per second for each storage algorithm.
4. **Memo** turns the counts into five controls: slow salted hashing, length over complexity, breach-list blocking, MFA, rate limiting.

## Known limits (good to say in an interview)

- Pool-based entropy **overrates dictionary words**: `Tr0ub4dor&3` scores "Very strong" here, but real crackers using word lists and mutation rules find it far faster. That is exactly why NIST and the NCSC moved towards long passphrases.
- The common-password list has 45 entries. Real systems check hundreds of millions.

## Make it yours (do at least one before you list it on your CV)

- [ ] Load a 10,000-word common-password file instead of the built-in set
- [ ] Add a dictionary check so `Tr0ub4dor&3` is rated correctly; write up the before/after
- [ ] Add a k-anonymity breach check (send only the first 5 characters of the SHA-1 hash)
- [ ] Add a CSV export and a chart of the rating mix

## Interview questions to be ready for

1. Why is a slow hash good for passwords but bad for checking file integrity?
2. What is a salt and what attack does it stop?
3. Why can forced complexity rules make passwords weaker in practice?
4. How does a k-anonymity breach check avoid sending the password anywhere?
