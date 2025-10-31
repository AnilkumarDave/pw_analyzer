#!/usr/bin/env python3
"""
Password Strength Analyzer & Breach Simulation
- Evaluate complexity (entropy estimate + heuristics)
- Simulate dictionary attack with optional mangling
- Simulate limited brute-force (configurable max attempts)
- Produce JSON/CSV/text report

Usage examples:
  python pw_analyzer.py --password "P@ssw0rd123" --dict common.txt --max-brute 100000 --report out.json
  python pw_analyzer.py --batch passwords.txt --dict common.txt --report report.csv
"""

import argparse
import hashlib
import itertools
import json
import csv
import sys
import time
import math
import time
import itertools
from typing import Tuple
from typing import List, Dict, Tuple

# ---------------------------
# Utilities / Config
# ---------------------------
DEFAULT_CHARSETS = {
    'lower': 'abcdefghijklmnopqrstuvwxyz',
    'upper': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    'digits': '0123456789',
    'symbols': "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
}

# thresholds in entropy bits
ENTROPY_THRESHOLDS = {
    'weak': 28,    # <28 bits considered weak
    'medium': 50   # 28-50 medium, >50 strong
}

# common leet substitutions for simple mangling
LEET = {
    '4': 'a', '0': 'o', '3': 'e', '1': 'l', '5': 's', '@': 'a', '$': 's'
}

# ---------------------------
# Strength / Entropy
# ---------------------------
def charset_from_password(pw: str) -> Tuple[int, List[str]]:
    used = []
    size = 0
    for k, chars in DEFAULT_CHARSETS.items():
        if any(c in chars for c in pw):
            used.append(k)
            size += len(chars)
    return size, used

def estimate_entropy(pw: str) -> float:
    # conservative charset estimate: count unique classes used
    charset_size, used_classes = charset_from_password(pw)
    if charset_size == 0:
        return 0.0
    # entropy bits = length * log2(charset_size)
    return len(pw) * math.log2(charset_size)

# ---------------------------
# Heuristics / Checks
# ---------------------------
def common_patterns_score(pw: str) -> Dict[str, bool]:
    lower = pw.lower()
    checks = {
        'is_all_lower': pw.islower(),
        'is_all_upper': pw.isupper(),
        'is_all_digits': pw.isdigit(),
        'has_repeated_char': any(pw.count(ch) > 3 for ch in set(pw)),
        'is_sequential_inc': any(''.join(s) in lower for s in (['0123456789'[i:i+4]] for i in range(6)) )  # placeholder (rare)
    }
    # simple keyboard sequences or year checks
    checks['looks_like_year'] = any(lower == str(y) for y in range(1900, 2031))
    return checks

def classify_entropy_bits(bits: float) -> str:
    if bits < ENTROPY_THRESHOLDS['weak']:
        return 'weak'
    if bits < ENTROPY_THRESHOLDS['medium']:
        return 'medium'
    return 'strong'

# ---------------------------
# Dictionary attack simulator
# ---------------------------
def wordlist_matches(password: str, wordlist: List[str], mangling: bool=True, max_checks:int=100000) -> Tuple[bool, int, str]:
    """
    Try direct matches and (optionally) simple mangles until found or max_checks reached.
    Returns (found, checks_done, matched_word_or_mangling)
    """
    checked = 0
    pw = password.strip()
    # direct check
    for w in wordlist:
        checked += 1
        if checked > max_checks:
            return False, checked, ''
        if w.strip() == pw:
            return True, checked, w.strip()
    if not mangling:
        return False, checked, ''

    # mangling examples: append digits, leet replace, capitalization
    # simple mangles only (safe & fast)
    for w in wordlist:
        base = w.strip()
        # capitalization variants
        tries = [base, base.capitalize(), base.upper()]
        # leet substitution variants (single substitution)
        leet_variants = set()
        for t in tries:
            leet_variants.add(t)
            s = list(t)
            for i, ch in enumerate(s):
                if ch.lower() in LEET.values():
                    continue
                for le, real in LEET.items():
                    if real == ch.lower():
                        s2 = s.copy()
                        s2[i] = le
                        leet_variants.add(''.join(s2))
        # append 1-3 digits
        for variant in leet_variants:
            for digits_len in range(0, 3):
                if digits_len == 0:
                    cand = variant
                    checked += 1
                    if checked > max_checks:
                        return False, checked, ''
                    if cand == pw:
                        return True, checked, f'{base} (mangled: {cand})'
                else:
                    # append numbers like 1..999 but limit to small set
                    for n in range(0, min(100, 10**digits_len)):
                        cand = f"{variant}{n}"
                        checked += 1
                        if checked > max_checks:
                            return False, checked, ''
                        if cand == pw:
                            return True, checked, f'{base} (mangled: {cand})'
    return False, checked, ''

# ---------------------------
# Brute-force simulator (limited)
# ---------------------------
def brute_force_simulator(password: str,
                          charset: str,
                          max_attempts: int = 100000,
                          max_len: int = 6,
                          max_seconds: float = None) -> Tuple[bool, int, str]:
    """
    Attempt to brute force by enumerating combinations.
    Stops when:
      - found, or
      - attempts > max_attempts, or
      - length > max_len, or
      - elapsed time > max_seconds (if provided).
    Returns (found, attempts, match).
    """
    target = password
    attempts = 0
    start = time.time()
    for length in range(1, max_len + 1):
        # iterate lexicographic guesses
        for tup in itertools.product(charset, repeat=length):
            attempts += 1
            # time cutoff
            if max_seconds is not None and (time.time() - start) > max_seconds:
                return False, attempts, ''
            if attempts > max_attempts:
                return False, attempts, ''
            # build guess and compare
            guess = ''.join(tup)
            if guess == target:
                return True, attempts, guess
    return False, attempts, ''
# ---------------------------
# Report helpers
# ---------------------------
def analyze_password(password: str, wordlist: List[str]=None, dict_mangling=True,
                     brute_charset: str=None, max_brute_attempts:int=10000, brute_max_len:int=5) -> Dict:
    pw = password.strip()
    result = {'password': pw}
    # basics
    result['length'] = len(pw)
    charset_size, used_classes = charset_from_password(pw)
    result['used_classes'] = used_classes
    result['charset_size_estimate'] = charset_size
    entropy = estimate_entropy(pw)
    result['entropy_bits'] = round(entropy, 2)
    result['classification'] = classify_entropy_bits(entropy)
    # heuristics
    result['heuristics'] = common_patterns_score(pw)

    # dictionary attack simulation
    dict_result = {'attempted': False, 'found': False, 'checks': 0, 'match': ''}
    if wordlist:
        dict_result['attempted'] = True
        found, checks, match = wordlist_matches(pw, wordlist, mangling=dict_mangling, max_checks=200000)
        dict_result.update({'found': found, 'checks': checks, 'match': match})
    result['dictionary_attack'] = dict_result

    # brute-force simulation
    brute_result = {'attempted': False, 'found': False, 'attempts': 0, 'match': ''}
    if brute_charset:
        brute_result['attempted'] = True
        found, attempts, match = brute_force_simulator(pw, brute_charset, max_attempts=max_brute_attempts, max_len=brute_max_len)
        brute_result.update({'found': found, 'attempts': attempts, 'match': match})
    result['brute_force_simulation'] = brute_result

    # suggestions
    suggestions = []
    if entropy < ENTROPY_THRESHOLDS['weak']:
        suggestions.append("Increase length. Aim for 12+ characters.")
    if 'lower' not in used_classes or 'upper' not in used_classes:
        suggestions.append("Mix lowercase and uppercase letters.")
    if 'digits' not in used_classes:
        suggestions.append("Add digits (0-9).")
    if 'symbols' not in used_classes:
        suggestions.append("Add symbols or punctuation characters.")
    if result['heuristics'].get('is_all_digits'):
        suggestions.append("Avoid using only digits (e.g., phone numbers or years).")
    if result['dictionary_attack']['found']:
        suggestions.append("This password is present or easily derived from common words â€” choose a unique passphrase or add complexity.")
    if result['brute_force_simulation']['found']:
        suggestions.append("This password was brute-forced in a limited simulation â€” change it to a stronger combination.")
    if not suggestions:
        suggestions.append("No immediate actionable suggestions â€” maintain unique passwords and use a password manager.")
    result['recommendations'] = suggestions
    return result

# ---------------------------
# IO / Main
# ---------------------------
def load_wordlist(path: str) -> List[str]:
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.rstrip('\n') for line in f if line.strip()]
    except Exception as e:
        print(f"Error loading dictionary file {path}: {e}", file=sys.stderr)
        return []

def save_report_json(report: List[Dict], outpath: str):
    with open(outpath, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    print(f"Saved JSON report to {outpath}")

def save_report_csv(report: List[Dict], outpath: str):
    # flatten selectively for CSV
    keys = ['password','length','charset_size_estimate','entropy_bits','classification','dictionary_attack_found','dictionary_attack_checks','brute_force_found','brute_force_attempts','recommendations']
    with open(outpath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(keys)
        for r in report:
            row = [
                r.get('password',''),
                r.get('length',''),
                r.get('charset_size_estimate',''),
                r.get('entropy_bits',''),
                r.get('classification',''),
                r.get('dictionary_attack',{}).get('found',False),
                r.get('dictionary_attack',{}).get('checks',0),
                r.get('brute_force_simulation',{}).get('found',False),
                r.get('brute_force_simulation',{}).get('attempts',0),
                "; ".join(r.get('recommendations',[]))
            ]
            writer.writerow(row)
    print(f"Saved CSV report to {outpath}")

def parse_args():
    parser = argparse.ArgumentParser(description='Password Strength Analyzer & Breach Simulator')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--password', '-p', help='Single password to analyze (wrap in quotes)')
    group.add_argument('--batch', '-b', help='File with one password per line to analyze')
    parser.add_argument('--dict', '-d', help='Path to dictionary/wordlist file for simulating dictionary attack')
    parser.add_argument('--no-dict-mangle', action='store_true', help='Disable simple mangling during dictionary simulation')
    parser.add_argument('--max-brute', type=int, default=10000, help='Max brute-force attempts to run per password (default 10000)')
    parser.add_argument('--brute-charset', help='Charset to use for brute-force simulation (default: lowercase+digits)', default=None)
    parser.add_argument('--brute-max-len', type=int, default=5, help='Maximum length to attempt in brute-force (default 5)')
    parser.add_argument('--report', '-r', help='Path to save report (.json or .csv). If omitted prints to stdout')
    return parser.parse_args()

def main():
    args = parse_args()
    wordlist = []
    if args.dict:
        wordlist = load_wordlist(args.dict)

    if args.brute_charset:
        brute_charset = args.brute_charset
    else:
        brute_charset = DEFAULT_CHARSETS['lower'] + DEFAULT_CHARSETS['digits']

    targets = []
    if args.password:
        targets = [args.password]
    else:
        # batch
        with open(args.batch, 'r', encoding='utf-8', errors='ignore') as f:
            targets = [line.rstrip('\n') for line in f if line.strip()]

    report = []
    start_ts = time.time()
    for pw in targets:
        print(f"Analyzing: {pw}")
        r = analyze_password(
            pw,
            wordlist=wordlist if wordlist else None,
            dict_mangling=not args.no_dict_mangle,
            brute_charset=brute_charset,
            max_brute_attempts=args.max_brute,
            brute_max_len=args.brute_max_len
        )
        report.append(r)
    elapsed = time.time() - start_ts
    print(f"Analysis complete for {len(report)} password(s) in {elapsed:.2f}s")

    if args.report:
        if args.report.lower().endswith('.json'):
            save_report_json(report, args.report)
        elif args.report.lower().endswith('.csv'):
            save_report_csv(report, args.report)
        else:
            # default to JSON
            save_report_json(report, args.report)
    else:
        # print human-readable report
        print(json.dumps(report, indent=2))

if __name__ == '__main__':
    main()

# --- compatibility wrapper added by assistant ---
# This wrapper accepts max_seconds and forwards to brute_force_simulator.
# It then replaces the module-level analyze_password reference so callers (GUI) can pass max_seconds.
def analyze_password_with_timeout(password: str, wordlist: List[str]=None, dict_mangling=True,
                     brute_charset: str=None, max_brute_attempts:int=10000, brute_max_len:int=5, max_seconds: float=None) -> Dict:
    pw = password.strip()
    result = {'password': pw}
    # basics
    result['length'] = len(pw)
    charset_size, used_classes = charset_from_password(pw)
    result['used_classes'] = used_classes
    result['charset_size_estimate'] = charset_size
    entropy = estimate_entropy(pw)
    result['entropy_bits'] = round(entropy, 2)
    result['classification'] = classify_entropy_bits(entropy)
    # heuristics
    result['heuristics'] = common_patterns_score(pw)

    # dictionary attack simulation
    dict_result = {'attempted': False, 'found': False, 'checks': 0, 'match': ''}
    if wordlist:
        dict_result['attempted'] = True
        found, checks, match = wordlist_matches(pw, wordlist, mangling=dict_mangling, max_checks=200000)
        dict_result.update({'found': found, 'checks': checks, 'match': match})
    result['dictionary_attack'] = dict_result

    # brute-force simulation
    brute_result = {'attempted': False, 'found': False, 'attempts': 0, 'match': ''}
    used_brute_charset = brute_charset if brute_charset else (DEFAULT_CHARSETS['lower'] + DEFAULT_CHARSETS['digits'])
    if used_brute_charset:
        brute_result['attempted'] = True
        found, attempts, match = brute_force_simulator(
            pw,
            used_brute_charset,
            max_attempts=max_brute_attempts,
            max_len=brute_max_len,
            max_seconds=max_seconds
        )
        brute_result.update({'found': found, 'attempts': attempts, 'match': match})
    result['brute_force_simulation'] = brute_result

    # suggestions
    suggestions = []
    if entropy < ENTROPY_THRESHOLDS['weak']:
        suggestions.append("Increase length. Aim for 12+ characters.")
    if 'lower' not in used_classes or 'upper' not in used_classes:
        suggestions.append("Mix lowercase and uppercase letters.")
    if 'digits' not in used_classes:
        suggestions.append("Add digits (0-9).")
    if 'symbols' not in used_classes:
        suggestions.append("Add symbols or punctuation characters.")
    if result['heuristics'].get('is_all_digits'):
        suggestions.append("Avoid using only digits (e.g., phone numbers or years).")
    if result['dictionary_attack']['found']:
        suggestions.append("This password is present or easily derived from common words — choose a unique passphrase or add complexity.")
    if result['brute_force_simulation']['found']:
        suggestions.append("This password was brute-forced in a limited simulation — change it to a stronger combination.")
    if not suggestions:
        suggestions.append("No immediate actionable suggestions — maintain unique passwords and use a password manager.")
    result['recommendations'] = suggestions
    return result

# Replace module-level analyze_password reference so GUI and CLI pick up the wrapper
analyze_password = analyze_password_with_timeout
# --- end wrapper ---
