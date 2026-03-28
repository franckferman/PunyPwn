#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PunyPwn - Domain Attack Surface Generator.

Enumerate typosquatting, IDN homograph, bitsquatting, and visual spoofing
candidates for a target domain. Built for red team engagements, phishing
simulation, threat hunting, and proactive brand protection.

Supported attack modules:
    idn           Cyrillic homograph substitution (Punycode/ACE encoding)
    homoglyph     ASCII-level visual lookalikes (rn->m, l->1, O->0)
    omission      Single character removed (gogle.com)
    repetition    Single character doubled (googgle.com)
    swap          Adjacent character transposition (googel.com)
    insertion     Extra character at each position (googale.com)
    replace       Adjacent keyboard key substitution (goofle.com)
    bitsquat      Single bit flip per character (googlg.com)
    tld           Common TLD typos (.com->.cm, .co, .om, .con)
    hyphen        Dot-to-hyphen / hyphen insertion (goo-gle.com)
    subdomain     Dot insertion to create fake subdomains (g.oogle.com)
    vowelswap     Swap vowels (googla.com, guogle.com)
    all           Run all modules

MITRE ATT&CK:
    T1566.002  Phishing: Spearphishing Link
    T1036      Masquerading
    T1583.001  Acquire Infrastructure: Domains
    T1598      Phishing for Information

Usage:
    python3 PunyPwn.py --domain google.com
    python3 PunyPwn.py --domain paypal.com --attack idn --style very-realistic
    python3 PunyPwn.py --domain microsoft.com --attack all --output results.json
    python3 PunyPwn.py --domain example.com --attack omission,swap,replace --quiet

Author:  Franck Ferman <franckferman@users.noreply.github.com>
License: GNU Affero General Public License v3.0
"""

import argparse
import csv
import itertools
import json
import string
import sys
from typing import List, Dict, Set, Optional, Tuple



# ==============================================================================
# CONSTANTS
# ==============================================================================

CYRILLIC_HOMOGLYPHS: Dict[str, str] = {
    'a': '\u0430', 'e': '\u0435', 'o': '\u043E', 'c': '\u0441',
    'p': '\u0440', 'x': '\u0445', 'y': '\u0443', 's': '\u0455',
    'i': '\u0456', 'j': '\u0458', 'q': '\u051B', 'd': '\u0501',
    'g': '\u0261', 'm': '\u043C', 't': '\u0442', 'k': '\u043A',
    'b': '\u044C', 'h': '\u04BB',
}

IDN_STYLES: Dict[str, List[str]] = {
    'any': list(CYRILLIC_HOMOGLYPHS.keys()),
    'realistic': ['a', 'e', 'o', 'c', 'p', 'x', 'y', 's', 'i', 'j'],
    'very-realistic': ['a', 'e', 'o', 'c', 's', 'i'],
}

ASCII_HOMOGLYPHS: Dict[str, List[str]] = {
    'l': ['1', 'i', '|'], '1': ['l', 'i'], 'i': ['l', '1', 'j'],
    'o': ['0'], '0': ['o'], 'O': ['0'],
    'rn': ['m'], 'cl': ['d'], 'vv': ['w'],
    'n': ['r'], 'u': ['v'], 'w': ['vv'],
    'd': ['cl'], 'm': ['rn', 'nn'],
}

QWERTY_NEIGHBORS: Dict[str, str] = {
    'q': 'wa', 'w': 'qase', 'e': 'wsdr', 'r': 'edft', 't': 'rfgy',
    'y': 'tghu', 'u': 'yhji', 'i': 'ujko', 'o': 'iklp', 'p': 'ol',
    'a': 'qwsz', 's': 'awedxz', 'd': 'serfcx', 'f': 'drtgvc',
    'g': 'ftyhbv', 'h': 'gyujnb', 'j': 'huikmn', 'k': 'jiolm',
    'l': 'kop', 'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb',
    'b': 'vghn', 'n': 'bhjm', 'm': 'njk',
}

VOWELS = 'aeiou'

COMMON_TLDS = ['.com', '.net', '.org', '.co', '.io', '.info', '.biz', '.xyz']

TLD_TYPOS: Dict[str, List[str]] = {
    '.com': ['.cm', '.co', '.om', '.con', '.comm', '.coom', '.vom', '.xom', '.cpm'],
    '.net': ['.ner', '.nwt', '.bet', '.met', '.ne', '.nett'],
    '.org': ['.og', '.rg', '.oeg', '.orgg', '.ofg'],
    '.fr': ['.dr', '.gr', '.fe', '.frr'],
    '.io': ['.oi', '.i0', '.ip', '.ioo'],
    '.co': ['.c0', '.xo', '.vo', '.coo'],
}


# ==============================================================================
# ATTACK MODULES
# ==============================================================================

def _to_punycode(label: str) -> str:
    """Encode a Unicode label to Punycode using the stdlib codec (RFC 3492)."""
    try:
        encoded = label.encode('punycode').decode('ascii')
        return f"xn--{encoded}" if encoded != label else label
    except (UnicodeError, UnicodeDecodeError):
        return label


def attack_idn(label: str, style: str = 'any', level: Optional[int] = None) -> List[Dict]:
    """IDN homograph attack: Cyrillic character substitution."""
    allowed = IDN_STYLES.get(style, IDN_STYLES['any'])
    positions = [i for i, c in enumerate(label) if c in allowed]

    if not positions:
        return []

    max_subs = level if level is not None else min(len(positions), 4)
    results = []

    for n in range(1, max_subs + 1):
        for subset in itertools.combinations(positions, n):
            chars = list(label)
            for idx in subset:
                chars[idx] = CYRILLIC_HOMOGLYPHS[chars[idx]]
            variant = "".join(chars)
            puny = _to_punycode(variant)
            detail = ', '.join(
                f"{label[i]}->{CYRILLIC_HOMOGLYPHS[label[i]]} (U+{ord(CYRILLIC_HOMOGLYPHS[label[i]]):04X})"
                for i in subset
            )
            results.append({'variant': variant, 'punycode': puny, 'detail': detail})

    return results


def attack_homoglyph(label: str) -> List[Dict]:
    """ASCII-level visual lookalike substitution (rn->m, l->1, etc.)."""
    results = []
    seen: Set[str] = set()

    # Single-char replacements
    for i, c in enumerate(label):
        if c in ASCII_HOMOGLYPHS:
            for replacement in ASCII_HOMOGLYPHS[c]:
                variant = label[:i] + replacement + label[i+1:]
                if variant != label and variant not in seen:
                    seen.add(variant)
                    results.append({'variant': variant, 'detail': f"{c}->{replacement} at pos {i}"})

    # Multi-char replacements (rn->m, cl->d, vv->w)
    for pattern, replacements in ASCII_HOMOGLYPHS.items():
        if len(pattern) > 1:
            idx = 0
            while idx < len(label):
                pos = label.find(pattern, idx)
                if pos == -1:
                    break
                for rep in replacements:
                    variant = label[:pos] + rep + label[pos+len(pattern):]
                    if variant not in seen:
                        seen.add(variant)
                        results.append({'variant': variant, 'detail': f"{pattern}->{rep} at pos {pos}"})
                idx = pos + 1

    return results


def attack_omission(label: str) -> List[Dict]:
    """Remove one character at a time."""
    results = []
    for i in range(len(label)):
        variant = label[:i] + label[i+1:]
        if variant:
            results.append({'variant': variant, 'detail': f"omit '{label[i]}' at pos {i}"})
    return results


def attack_repetition(label: str) -> List[Dict]:
    """Double one character at a time."""
    results = []
    seen: Set[str] = set()
    for i in range(len(label)):
        variant = label[:i] + label[i] + label[i:]
        if variant not in seen:
            seen.add(variant)
            results.append({'variant': variant, 'detail': f"repeat '{label[i]}' at pos {i}"})
    return results


def attack_swap(label: str) -> List[Dict]:
    """Transpose adjacent characters."""
    results = []
    for i in range(len(label) - 1):
        chars = list(label)
        chars[i], chars[i+1] = chars[i+1], chars[i]
        variant = "".join(chars)
        if variant != label:
            results.append({'variant': variant, 'detail': f"swap '{label[i]}'/'{label[i+1]}' at pos {i}/{i+1}"})
    return results


def attack_insertion(label: str) -> List[Dict]:
    """Insert one character at each position (a-z, 0-9)."""
    results = []
    seen: Set[str] = set()
    for i in range(len(label) + 1):
        for c in string.ascii_lowercase + string.digits:
            variant = label[:i] + c + label[i:]
            if variant != label and variant not in seen:
                seen.add(variant)
                results.append({'variant': variant, 'detail': f"insert '{c}' at pos {i}"})
    return results


def attack_replace(label: str) -> List[Dict]:
    """Replace each character with adjacent keyboard keys."""
    results = []
    seen: Set[str] = set()
    for i, c in enumerate(label):
        neighbors = QWERTY_NEIGHBORS.get(c.lower(), '')
        for n in neighbors:
            variant = label[:i] + n + label[i+1:]
            if variant != label and variant not in seen:
                seen.add(variant)
                results.append({'variant': variant, 'detail': f"'{c}'->'{n}' (adjacent key) at pos {i}"})
    return results


def attack_bitsquat(label: str) -> List[Dict]:
    """Flip each bit of each character (bitsquatting)."""
    results = []
    seen: Set[str] = set()
    for i, c in enumerate(label):
        for bit in range(8):
            flipped = chr(ord(c) ^ (1 << bit))
            if flipped.isalnum() or flipped == '-':
                variant = label[:i] + flipped + label[i+1:]
                if variant != label and variant not in seen:
                    seen.add(variant)
                    results.append({'variant': variant, 'detail': f"bit {bit} flip '{c}'->'{flipped}' at pos {i}"})
    return results


def attack_tld(domain: str) -> List[Dict]:
    """Generate TLD typos for the full domain."""
    results = []
    dot = domain.rfind('.')
    if dot == -1:
        return results

    label = domain[:dot]
    tld = domain[dot:]

    # Known TLD typos
    if tld in TLD_TYPOS:
        for typo in TLD_TYPOS[tld]:
            results.append({'variant': label + typo, 'detail': f"tld {tld}->{typo}"})

    # Missing dot typo: googl.ecom -> googlecom
    results.append({'variant': label + tld.replace('.', ''), 'detail': f"missing dot: {tld}->{''.join(tld.split('.'))}"})

    return results


def attack_hyphen(label: str) -> List[Dict]:
    """Insert hyphens at each position."""
    results = []
    for i in range(1, len(label)):
        variant = label[:i] + '-' + label[i:]
        results.append({'variant': variant, 'detail': f"hyphen at pos {i}"})
    return results


def attack_subdomain(label: str) -> List[Dict]:
    """Insert dots to create fake subdomains (g.oogle -> looks like subdomain)."""
    results = []
    for i in range(1, len(label)):
        variant = label[:i] + '.' + label[i:]
        results.append({'variant': variant, 'detail': f"dot at pos {i}: {label[:i]}.{label[i:]}"})
    return results


def attack_vowelswap(label: str) -> List[Dict]:
    """Swap each vowel with other vowels."""
    results = []
    seen: Set[str] = set()
    for i, c in enumerate(label):
        if c.lower() in VOWELS:
            for v in VOWELS:
                if v != c.lower():
                    variant = label[:i] + v + label[i+1:]
                    if variant not in seen:
                        seen.add(variant)
                        results.append({'variant': variant, 'detail': f"vowel '{c}'->'{v}' at pos {i}"})
    return results


ATTACK_MODULES = {
    'idn': None,  # special handling (needs style/level)
    'homoglyph': attack_homoglyph,
    'omission': attack_omission,
    'repetition': attack_repetition,
    'swap': attack_swap,
    'insertion': attack_insertion,
    'replace': attack_replace,
    'bitsquat': attack_bitsquat,
    'tld': None,  # special handling (needs full domain)
    'hyphen': attack_hyphen,
    'subdomain': attack_subdomain,
    'vowelswap': attack_vowelswap,
}

ALL_ATTACKS = list(ATTACK_MODULES.keys())


# ==============================================================================
# CORE ENGINE
# ==============================================================================

def split_domain(domain: str) -> Tuple[str, str]:
    """Split a domain into (label, tld). Returns (domain, '') if no TLD found."""
    dot = domain.rfind('.')
    if dot == -1 or dot == 0:
        return domain, ''
    return domain[:dot], domain[dot:]


def run_attacks(
    domain: str,
    attacks: List[str],
    style: str = 'any',
    level: Optional[int] = None,
    tlds: Optional[List[str]] = None,
) -> List[Dict]:
    """
    Run specified attack modules against a domain and return all variants.

    Returns a list of dicts with keys: domain, variant, attack, detail, punycode (optional).
    """
    label, orig_tld = split_domain(domain)
    if not orig_tld and tlds:
        orig_tld = tlds[0]

    all_results: List[Dict] = []
    seen_variants: Set[str] = set()

    for attack_name in attacks:
        variants: List[Dict] = []

        if attack_name == 'idn':
            raw = attack_idn(label, style=style, level=level)
            for r in raw:
                full = r['variant'] + orig_tld
                puny_full = r.get('punycode', r['variant']) + orig_tld
                if full not in seen_variants:
                    seen_variants.add(full)
                    all_results.append({
                        'domain': domain,
                        'variant': full,
                        'punycode': puny_full,
                        'attack': 'idn',
                        'detail': r['detail'],
                    })
            continue

        if attack_name == 'tld':
            raw = attack_tld(domain)
            for r in raw:
                v = r['variant']
                if v not in seen_variants:
                    seen_variants.add(v)
                    all_results.append({
                        'domain': domain,
                        'variant': v,
                        'attack': 'tld',
                        'detail': r['detail'],
                    })
            continue

        # Standard label-based attacks
        func = ATTACK_MODULES.get(attack_name)
        if func is None:
            continue

        raw = func(label)
        for r in raw:
            full = r['variant'] + orig_tld
            if full not in seen_variants:
                seen_variants.add(full)
                all_results.append({
                    'domain': domain,
                    'variant': full,
                    'attack': attack_name,
                    'detail': r['detail'],
                })

    return all_results


# ==============================================================================
# OUTPUT
# ==============================================================================

def export_results(results: List[Dict], filepath: str, fmt: Optional[str] = None):
    """Export results to file (csv, json, or txt)."""
    if fmt is None:
        if filepath.endswith('.json'):
            fmt = 'json'
        elif filepath.endswith('.csv'):
            fmt = 'csv'
        else:
            fmt = 'txt'

    with open(filepath, 'w', newline='', encoding='utf-8') as fh:
        if fmt == 'json':
            json.dump(results, fh, indent=2, ensure_ascii=False)
        elif fmt == 'csv':
            if results:
                writer = csv.DictWriter(fh, fieldnames=results[0].keys())
                writer.writeheader()
                writer.writerows(results)
        else:
            for r in results:
                fh.write(f"{r['variant']}\n")


def print_results(results: List[Dict], quiet: bool = False):
    """Print results to stdout."""
    if quiet:
        for r in results:
            print(r['variant'])
        return

    current_attack = None
    for r in results:
        if r['attack'] != current_attack:
            current_attack = r['attack']
            print(f"\n\033[91m[{current_attack.upper()}]\033[0m")
            print("-" * 64)

        puny = r.get('punycode', '')
        if puny and puny != r['variant']:
            print(f"  {r['variant']:<40s} {puny}")
        else:
            print(f"  {r['variant']}")


# ==============================================================================
# CLI
# ==============================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog='PunyPwn',
        description=(
            'PunyPwn - Domain Attack Surface Generator.\n\n'
            'Enumerate typosquatting, IDN homograph, bitsquatting, and visual\n'
            'spoofing candidates for red team, threat hunting, and brand protection.'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            'Attack modules:\n'
            '  idn         Cyrillic homograph substitution (Punycode)\n'
            '  homoglyph   ASCII visual lookalikes (rn->m, l->1)\n'
            '  omission    Single character removed\n'
            '  repetition  Single character doubled\n'
            '  swap        Adjacent character transposition\n'
            '  insertion   Extra character at each position\n'
            '  replace     Adjacent keyboard key substitution\n'
            '  bitsquat    Single bit flip per character\n'
            '  tld         Common TLD typos\n'
            '  hyphen      Hyphen insertion\n'
            '  subdomain   Dot insertion (fake subdomains)\n'
            '  vowelswap   Vowel substitution\n'
            '  all         Run all modules\n\n'
            'Examples:\n'
            '  python3 PunyPwn.py --domain google.com\n'
            '  python3 PunyPwn.py --domain paypal.com --attack idn --style very-realistic\n'
            '  python3 PunyPwn.py --domain microsoft.com --attack all --output results.json\n'
            '  python3 PunyPwn.py --domain example.com --attack omission,swap,replace -q\n'
            '  python3 PunyPwn.py --batch targets.txt --attack all --output campaign.csv\n\n'
            'MITRE ATT&CK: T1566.002, T1036, T1583.001, T1598'
        ),
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--domain', '-d', help='Target domain (e.g. google.com, paypal.com)')
    source.add_argument('--batch', '-b', metavar='FILE', help='File with domains (one per line)')

    parser.add_argument('--attack', '-a', default='all',
                        help='Comma-separated attack modules or "all" (default: all)')
    parser.add_argument('--style', choices=list(IDN_STYLES.keys()), default='any',
                        help='IDN substitution fidelity: any | realistic | very-realistic')
    parser.add_argument('--level', type=int, metavar='N',
                        help='IDN max simultaneous substitutions (default: 4)')
    parser.add_argument('--output', '-o', metavar='FILE',
                        help='Export to file (.json, .csv, .txt)')
    parser.add_argument('--format', choices=['csv', 'json', 'txt'],
                        help='Override export format')
    parser.add_argument('--quiet', '-q', action='store_true',
                        help='One domain per line (pipe-friendly)')
    parser.add_argument('--count', action='store_true',
                        help='Print count only')
    return parser.parse_args()


def main():
    args = parse_args()

    # Parse attacks
    if args.attack == 'all':
        attacks = ALL_ATTACKS
    else:
        attacks = [a.strip() for a in args.attack.split(',')]
        invalid = [a for a in attacks if a not in ATTACK_MODULES]
        if invalid:
            print(f"[!] Unknown attack module(s): {', '.join(invalid)}", file=sys.stderr)
            print(f"    Available: {', '.join(ALL_ATTACKS)}", file=sys.stderr)
            sys.exit(1)

    # Load domains
    domains: List[str] = []
    if args.batch:
        try:
            with open(args.batch, 'r', encoding='utf-8') as fh:
                domains = [l.strip().lower() for l in fh if l.strip() and not l.startswith('#')]
        except FileNotFoundError:
            print(f"[!] File not found: {args.batch}", file=sys.stderr)
            sys.exit(1)
    else:
        domains = [args.domain.lower()]

    all_results: List[Dict] = []

    for domain in domains:
        if not args.quiet and not args.count:
            print(f"\n\033[94m[*]\033[0m Target: {domain}")
            print(f"\033[94m[*]\033[0m Attacks: {', '.join(attacks)}")

        results = run_attacks(
            domain=domain,
            attacks=attacks,
            style=args.style,
            level=args.level,
        )
        all_results.extend(results)

        if args.count:
            by_attack = {}
            for r in results:
                by_attack.setdefault(r['attack'], 0)
                by_attack[r['attack']] += 1
            for a, c in sorted(by_attack.items()):
                print(f"  {a:<14s} {c:>6d}")
            print(f"  {'TOTAL':<14s} {len(results):>6d}")
        elif not args.quiet:
            print_results(results)
        else:
            print_results(results, quiet=True)

    if args.output and all_results:
        export_results(all_results, args.output, args.format)
        if not args.quiet:
            print(f"\n\033[94m[+]\033[0m {len(all_results)} variant(s) exported to '{args.output}'")

    if not args.quiet and not args.count:
        print(f"\n\033[94m[*]\033[0m Total: {len(all_results)} candidate domain(s)")


if __name__ == "__main__":
    main()
