# ZeroJ4ck

ZeroJ4ck is a browser-based clickjacking scanner that focuses on real behavior instead of header assumptions.
The tool crawls a website, collects internal pages, and checks whether each page can be embedded inside an iframe using a real Chromium browser. If a page embeds successfully, it is considered vulnerable.
Each scan generates standalone HTML proof-of-concept (PoC) files that can be opened directly or attached to bug bounty reports.

---

## Features

- Same-domain website crawling
- Unlimited crawling by default
- Optional crawl depth and page limits
- Real browser iframe verification using Playwright
- One PoC HTML file per tested URL
- Separate result folder for each scan
- Single target and bulk target support
- Clear terminal output for crawling and scanning phases

---

## Requirements

- Python 3.9 or higher
- Playwright (Chromium)
- Internet connection for browser checks

Tested on Windows and Linux.

---

## Installation

```bash
pip install -r requirements.txt
playwright install chromium
```

> Note: Installing Playwright with pip is not enough.  
> You must run `playwright install chromium` at least once.

---

## Usage

### Scan a single website

```bash
python clickjacking_scanner.py -u https://example.com
```

---

### Scan without crawling (single page only)

```bash
python clickjacking_scanner.py -u https://example.com --no-crawl
```

---

### Bulk scan multiple websites

Create a file with target URLs (one per line):

```txt
https://example.com
https://testphp.vulnweb.com
https://www.cbse.gov.in
```

Run:

```bash
python clickjacking_scanner.py -f targets.txt
```

Each target is scanned independently and saved in its own result folder.

---

### Limit crawling

Limit number of pages:

```bash
python clickjacking_scanner.py -u https://example.com --max-pages 20
```

Limit crawl depth:

```bash
python clickjacking_scanner.py -u https://example.com --max-depth 2
```

If no limits are provided, crawling is unlimited.

---

## Output Structure

Each scan creates a dedicated directory:

```
results/
└── scan_example_com_2025-01-15_11-42-10/
    ├── results.json
    ├── results.txt
    └── poc/
        ├── example_com_index.html
        ├── example_com_login.html
        └── example_com_dashboard.html
```

- `results.json` – structured scan output  
- `results.txt` – human-readable summary  
- `poc/` – standalone iframe PoC HTML files

---

## Detection Logic

The detection logic is intentionally simple:

> If a page successfully embeds inside an iframe in a real browser, it is treated as vulnerable.

No reliance on HTTP headers or theoretical checks.

---

## Use Cases

- Bug bounty reconnaissance
- Quick clickjacking validation
- Generating clean iframe PoCs
- Understanding iframe behavior in real browsers

---

## Limitations

ZeroJ4ck does not:
- Bypass frame-busting JavaScript
- Handle authentication or logged-in sessions
- Exploit UI redressing chains
- Claim business impact beyond iframe embedding

---

## Legal Notice

Use this tool only on systems you own or have explicit permission to test.  
The author is not responsible for misuse.

---

## Final Note

ZeroJ4ck is designed to be simple, transparent, and honest about what it does.

If the browser allows iframe embedding, you’ll see it.  
If it doesn’t, you won’t.
