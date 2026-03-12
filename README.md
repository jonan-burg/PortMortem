# PortMortem 🔍

**A port scanning and CVE risk assessment tool built on Nmap and the National Vulnerability Database.**

---

PortMortem scans a target machine or network, fingerprints the services running on open ports, and checks each one against known CVEs. The result is a prioritized risk report — so instead of staring at raw Nmap output, you get a clear picture of what's actually exposed and how bad it is.

---

## What it does

- Runs an Nmap `-sV` scan to detect open ports and service versions
- Looks up each service against the NVD API for known CVEs
- Scores findings by CVSS severity (Critical → Low)
- Prints a color-coded summary table in the terminal
- Exports a standalone HTML report to the `reports/` folder

---

## Stack

- **Python 3.10+**
- **Nmap** — scanning engine
- **python-nmap** — Python wrapper around Nmap
- **NVD REST API v2.0** — CVE + CVSS data
- **Rich** — terminal output formatting
- **Requests** — HTTP

---

## Project layout

```
portmortem/
├── main.py          # entry point
├── scanner.py       # nmap wrapper + parser
├── nvd_client.py    # nvd api calls
├── scorer.py        # cvss scoring logic
├── reporter.py      # terminal + html output
├── requirements.txt
├── .env             # put your NVD_API_KEY here
└── reports/         # generated html reports land here
```

---

## Setup

You'll need Nmap installed and a free NVD API key.

**Get an NVD API key:** https://nvd.nist.gov/developers/request-an-api-key

**Install Nmap:**
```bash
sudo apt install nmap      # Debian/Ubuntu
brew install nmap          # macOS
# Windows: https://nmap.org/download.html
```

**Install Python dependencies:**
```bash
pip install -r requirements.txt
```

**Add your API key:**
```bash
echo "NVD_API_KEY=your_key_here" > .env
```

---

## Usage

```bash
# scan a single host
python main.py --target 192.168.1.1

# scan a subnet
python main.py --target 192.168.1.0/24

# save an HTML report
python main.py --target 192.168.1.1 --report
```

**Sample output:**
```
PortMortem — starting scan on 192.168.1.1

  PORT    SERVICE    VERSION       CVEs    SEVERITY
  22      OpenSSH    7.4           12      HIGH
  80      Apache     2.4.29        8       MEDIUM
  443     OpenSSL    1.0.2k        21      CRITICAL
  3306    MySQL      5.7.31        3       LOW

  Overall risk score: 7.8 / 10
  Report saved → reports/20240115_192.168.1.1.html
```

---

## Scoring

CVSS v3 base scores from the NVD, bucketed as:

| Score     | Label    |
|-----------|----------|
| 9.0–10.0  | Critical |
| 7.0–8.9   | High     |
| 4.0–6.9   | Medium   |
| 0.1–3.9   | Low      |

The overall score is a weighted average of the top CVEs found across all services.

---

## Disclaimer

Only scan systems you own or have explicit permission to test. Unauthorized scanning is illegal in most places. This tool is for educational and authorized use only.

---

## Roadmap

- [x] Nmap scanning + version detection
- [x] NVD CVE lookup
- [x] CVSS risk scoring
- [x] Terminal report + HTML export
- [ ] JSON output
- [ ] Scan diffing (detect changes between runs)
- [ ] Email delivery for reports
- [ ] Simple web UI

---

## Author

[Your Name] — built as a student project exploring network security and vulnerability assessment.
