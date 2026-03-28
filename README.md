<div id="top" align="center">

[![Contributors][contributors-shield]](https://github.com/franckferman/PunyPwn/graphs/contributors)
[![Stargazers][stars-shield]](https://github.com/franckferman/PunyPwn/stargazers)
[![License][license-shield]](https://github.com/franckferman/PunyPwn/blob/stable/LICENSE)

<h3 align="center">PunyPwn</h3>
<p align="center">
  <em>Domain Attack Surface Generator.</em><br>
  Enumerate typosquatting, IDN homograph, bitsquatting, and visual spoofing candidates for red team engagements, threat hunting, and brand protection.
</p>

**[Site](https://franckferman.github.io/PunyPwn/) &middot; [Documentation](#usage)**

</div>

---

## Table of Contents

<details open>
  <summary><strong>Expand / Collapse</strong></summary>
  <ol>
    <li><a href="#overview">Overview</a></li>
    <li><a href="#attack-modules">Attack Modules</a></li>
    <li><a href="#mitre-attck-mapping">MITRE ATT&CK Mapping</a></li>
    <li><a href="#installation">Installation</a></li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#examples">Examples</a></li>
    <li><a href="#detection-and-mitigation">Detection and Mitigation</a></li>
    <li><a href="#legal-disclaimer">Legal Disclaimer</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
  </ol>
</details>

---

## Overview

PunyPwn is a domain attack surface generator that enumerates every plausible spoofing variant of a target domain. It covers 12 attack techniques from simple typos to advanced Unicode homograph injection, producing a structured list of candidate domains for:

- **Red team / phishing simulation**: identify registrable domains that visually impersonate the target
- **Threat hunting**: enumerate lookalikes to monitor via CT logs, passive DNS, or SIEM queries
- **Brand protection**: proactively register or takedown squatted variants before adversaries do
- **Security research**: study the attack surface exposed by IDN, typosquatting, and bitsquatting

Zero external dependencies. All 12 modules use the Python standard library exclusively.

---

## Attack Modules

PunyPwn implements 12 independent attack modules. Each can be run individually or combined.

| Module | Technique | Example (`google.com`) |
|---|---|---|
| `idn` | Cyrillic homograph substitution (Punycode) | `gооgle.com` (Cyrillic o) -> `xn--ggle-55da.com` |
| `homoglyph` | ASCII visual lookalikes (rn->m, l->1, O->0) | `goog1e.com`, `googie.com` |
| `omission` | Single character removed | `gogle.com`, `goole.com` |
| `repetition` | Single character doubled | `googgle.com`, `gooogle.com` |
| `swap` | Adjacent character transposition | `googel.com`, `ogogle.com` |
| `insertion` | Extra character at each position | `googale.com`, `goohgle.com` |
| `replace` | QWERTY adjacent key substitution | `goofle.com`, `googke.com` |
| `bitsquat` | Single bit flip per character (bitsquatting) | `googlg.com`, `coogle.com` |
| `tld` | Common TLD typos and lookalikes | `google.cm`, `google.co`, `google.con` |
| `hyphen` | Hyphen insertion | `goo-gle.com`, `g-oogle.com` |
| `subdomain` | Dot insertion (fake subdomains) | `g.oogle.com`, `goo.gle.com` |
| `vowelswap` | Vowel substitution | `googla.com`, `guogle.com` |

Run all modules with `--attack all` or select specific ones with `--attack omission,swap,replace`.

### IDN Homograph Styles

The IDN module supports three fidelity tiers controlling which Cyrillic substitutions are used:

| Style | Characters | Fidelity |
|---|---|---|
| `any` | a e o c p x y s i j q d g m t k b h (18) | All substitutions |
| `realistic` | a e o c p x y s i j (10) | High visual similarity |
| `very-realistic` | a e o c s i (6) | Pixel-identical in most typefaces |

---

## MITRE ATT&CK Mapping

| Technique | ID | Tactic | Relevance |
|---|---|---|---|
| Phishing: Spearphishing Link | T1566.002 | Initial Access | Homograph/typo domains in phishing emails |
| Masquerading | T1036 | Defense Evasion | Domain spoofing at DNS/TLS layer |
| Acquire Infrastructure: Domains | T1583.001 | Resource Development | Registration of generated candidates |
| Phishing for Information | T1598 | Reconnaissance | Credential harvesting via clone sites |

---

## Installation

**Python 3** (standard library only, zero external dependencies).

```bash
git clone https://github.com/franckferman/PunyPwn.git
cd PunyPwn
python3 PunyPwn.py --domain example.com
```

No `pip install` needed. All 12 modules use the Python standard library exclusively.

---

## Usage

### Parameters

| Parameter | Default | Description |
|---|---|---|
| `--domain / -d` | - | Target domain with TLD (e.g. `google.com`) |
| `--batch / -b` | - | File with domains (one per line) |
| `--attack / -a` | `all` | Comma-separated modules or `all` |
| `--style` | `any` | IDN fidelity filter: `any`, `realistic`, `very-realistic` |
| `--level` | `4` | IDN max simultaneous substitutions |
| `--output / -o` | - | Export to file (auto-detect: .json, .csv, .txt) |
| `--format` | auto | Override export format |
| `--quiet / -q` | off | One domain per line (pipe-friendly) |
| `--count` | off | Show count by module, no listing |

---

## Examples

### Full attack surface enumeration

```bash
python3 PunyPwn.py --domain google.com
```

### Targeted modules

```bash
# Typos only (fastest, most common real-world squats)
python3 PunyPwn.py -d paypal.com --attack omission,swap,replace,repetition

# IDN-only with highest fidelity
python3 PunyPwn.py -d paypal.com --attack idn --style very-realistic --level 2

# Bitsquatting candidates
python3 PunyPwn.py -d microsoft.com --attack bitsquat
```

### Export for toolchain integration

```bash
# JSON export for automation
python3 PunyPwn.py -d example.com --attack all --output results.json

# CSV for spreadsheet analysis
python3 PunyPwn.py -d example.com --attack all --output results.csv

# Quiet mode: pipe into dig, whois, or registration check
python3 PunyPwn.py -d example.com --attack omission,swap -q | xargs -I{} dig +short {}

# Check which variants are registered
python3 PunyPwn.py -d paypal.com -q --attack tld,omission | while read d; do
  if dig +short "$d" | grep -q '.'; then echo "[LIVE] $d"; fi
done
```

### Batch mode

```bash
# Process multiple targets
echo -e "google.com\npaypal.com\nmicrosoft.com" > targets.txt
python3 PunyPwn.py --batch targets.txt --attack all --output campaign.json
```

### Count mode (no listing)

```bash
python3 PunyPwn.py -d google.com --count
```

---

## Detection and Mitigation

### Network controls

- Deploy DNS filtering (Cisco Umbrella, Quad9, Pi-hole) to flag `xn--` resolutions matching brand patterns
- Monitor DNS query logs for Punycode labels and known typosquatting variants
- Implement DMARC, DKIM, and SPF; extend monitoring to lookalike domains

### Browser controls

- Modern browsers apply mixed-script heuristics and display Punycode for deceptive IDN labels
- Extensions: IDN Safe, uBlock Origin with appropriate filter lists

### Proactive registration

- Register common homograph and typo variants of your brand domains pre-emptively
- Use PunyPwn itself to enumerate candidates and lock them down

### CT log monitoring

- Monitor certificate transparency logs (crt.sh, Certstream) for certificates issued to lookalike domains

### Detection signatures

```
# Suricata / Snort - IDN Punycode queries
alert dns any any -> any 53 (msg:"IDN Punycode domain query"; dns.query; content:"xn--"; nocase; sid:9000001; rev:1;)
```

```
# Splunk - hunt xn-- resolutions
index=dns query="xn--*" | stats count by query, src_ip | sort -count
```

---

## Legal Disclaimer

PunyPwn is a security research and educational tool created to demonstrate domain spoofing attack surface for authorised assessments.

This tool must only be used on domains and infrastructure for which you have explicit written authorisation. Registering lookalike domains with intent to deceive users, harvest credentials, or impersonate organisations is illegal in most jurisdictions.

You are solely responsible for your use of this tool and any consequences that arise from it.

---

## License

This project is licensed under the GNU Affero General Public License v3.0. See [LICENSE](https://github.com/franckferman/PunyPwn/blob/stable/LICENSE).

---

## Contact

[![ProtonMail][protonmail-shield]](mailto:contact@franckferman.fr)
[![LinkedIn][linkedin-shield]](https://www.linkedin.com/in/franckferman)
[![Twitter][twitter-shield]](https://www.twitter.com/franckferman)

<p align="right">(<a href="#top">Back to top</a>)</p>

<!-- MARKDOWN LINKS & IMAGES -->
[contributors-shield]: https://img.shields.io/github/contributors/franckferman/PunyPwn.svg?style=for-the-badge
[stars-shield]: https://img.shields.io/github/stars/franckferman/PunyPwn.svg?style=for-the-badge
[license-shield]: https://img.shields.io/github/license/franckferman/PunyPwn.svg?style=for-the-badge
[protonmail-shield]: https://img.shields.io/badge/ProtonMail-8B89CC?style=for-the-badge&logo=protonmail&logoColor=white
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=blue
[twitter-shield]: https://img.shields.io/badge/-Twitter-black.svg?style=for-the-badge&logo=twitter&colorB=blue
