#!/usr/bin/env python3
import argparse
import json
import os
import re
from collections import deque
from datetime import datetime
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright

# =============================
# Terminal Colors
# =============================
class C:
    RED = "\033[91m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    END = "\033[0m"
    BOLD = "\033[1m"

# =============================
# Banner (RED)
# =============================
def print_banner():
    banner = r"""
 ________                            _____  _    _           __       
|  __   _|                          |_   _|| |  | |         [  |  _   
|_/  / /   .---.  _ .--.   .--.       | |  | |__| |_  .---.  | | / ]  
   .'.' _ / /__\\[ `/'`\]/ .'`\ \ _   | |  |____   _|/ /'`\] | '' <   
 _/ /__/ || \__., | |    | \__. || |__' |      _| |_ | \__.  | |`\ \  
|________| '.__.'[___]    '.__.' `.____.'     |_____|'.___.'[__|  \_] 
                                                                      
                            CIpher
"""
    print(f"{C.RED}{banner}{C.END}")

# =============================
# Config
# =============================
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}

BASE_RESULTS_DIR = "results"

# =============================
# Helpers
# =============================
def normalize_url(url):
    url = url.strip()
    if not url:
        return None
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url

def same_domain(u1, u2):
    return urlparse(u1).netloc == urlparse(u2).netloc

def safe_filename_from_url(url):
    parsed = urlparse(url)
    path = parsed.path.strip("/") or "index"
    name = parsed.netloc + "_" + path
    name = re.sub(r"[^a-zA-Z0-9_\-]", "_", name)
    return name[:150] + ".html"

def create_scan_folder(target_url):
    domain = urlparse(target_url).netloc.replace(":", "_")
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    scan_dir = os.path.join(BASE_RESULTS_DIR, f"scan_{domain}_{ts}")
    poc_dir = os.path.join(scan_dir, "poc")
    os.makedirs(poc_dir, exist_ok=True)
    return scan_dir, poc_dir

def load_targets(single_url=None, file_path=None):
    targets = []

    if single_url:
        u = normalize_url(single_url)
        if u:
            targets.append(u)

    if file_path:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                u = normalize_url(line)
                if u:
                    targets.append(u)

    seen = set()
    final = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            final.append(t)

    return final

# =============================
# PHASE 1: CRAWLER
# =============================
def crawl_website(base_url, max_pages=None, max_depth=None):
    visited = set()
    queue = deque([(base_url, 0)])
    discovered = []

    print(f"{C.BOLD}{C.BLUE}[CRAWLING STARTED]{C.END} {base_url}\n")

    while queue:
        current, depth = queue.popleft()

        if current in visited:
            continue
        if max_pages is not None and len(visited) >= max_pages:
            break

        visited.add(current)
        discovered.append(current)
        print(f"{C.BLUE}[CRAWL]{C.END} {current}")

        if max_depth is not None and depth >= max_depth:
            continue

        try:
            r = requests.get(current, headers=HEADERS, timeout=10)
            if "text/html" not in r.headers.get("Content-Type", ""):
                continue

            soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.find_all("a", href=True):
                full = urljoin(current, a["href"]).split("#")[0].strip()
                if same_domain(full, base_url) and full not in visited:
                    queue.append((full, depth + 1))
        except Exception:
            continue

    print(f"\n{C.GREEN}[CRAWL COMPLETE]{C.END} Pages discovered: {len(discovered)}\n")
    return discovered

# =============================
# PoC Generator
# =============================
def generate_poc_html(url):
    return f"""<!DOCTYPE html>
<html>
<body>
<h3>Clickjacking PoC</h3>
<iframe src="{url}" width="800" height="600" style="border:2px solid red;"></iframe>
</body>
</html>
"""

# =============================
# Playwright Check
# =============================
def iframe_loads(target_url):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        try:
            page.set_content(generate_poc_html(target_url),
                             wait_until="domcontentloaded",
                             timeout=5000)
            page.wait_for_timeout(2000)
            iframe = page.query_selector("iframe")
            if iframe and iframe.get_attribute("src") == target_url:
                browser.close()
                return True
        except Exception:
            browser.close()
            return False
        browser.close()
        return False

# =============================
# PHASE 2: SCAN
# =============================
def scan_all(urls, poc_dir):
    results = []
    print(f"{C.BOLD}{C.YELLOW}[SCANNING STARTED]{C.END} Total pages: {len(urls)}\n")

    for i, url in enumerate(urls, 1):
        print(f"{C.YELLOW}[SCAN {i}/{len(urls)}]{C.END} {url}")

        poc_name = safe_filename_from_url(url)
        with open(os.path.join(poc_dir, poc_name), "w", encoding="utf-8") as f:
            f.write(generate_poc_html(url))

        vulnerable = iframe_loads(url)

        if vulnerable:
            print(f"  {C.RED}[VULNERABLE]{C.END}\n")
        else:
            print("  [SAFE]\n")

        results.append({
            "url": url,
            "vulnerable": vulnerable,
            "poc_file": f"poc/{poc_name}"
        })

    return results

# =============================
# Export
# =============================
def export_results(results, scan_dir):
    with open(os.path.join(scan_dir, "results.json"), "w") as f:
        json.dump(results, f, indent=4)

# =============================
# Main
# =============================
def main():
    print_banner()

    parser = argparse.ArgumentParser(description="ZeroJ4ck – Clickjacking Scanner")
    parser.add_argument("-u", "--url")
    parser.add_argument("-f", "--file")
    parser.add_argument("--max-pages", type=int)
    parser.add_argument("--max-depth", type=int)
    parser.add_argument("--no-crawl", action="store_true")
    args = parser.parse_args()

    targets = load_targets(args.url, args.file)

    for target in targets:
        scan_dir, poc_dir = create_scan_folder(target)

        if args.no_crawl:
            urls = [target]
        else:
            urls = crawl_website(target, args.max_pages, args.max_depth)

        results = scan_all(urls, poc_dir)
        export_results(results, scan_dir)

        print(f"{C.GREEN}[DONE]{C.END} Results saved in {scan_dir}\n")

if __name__ == "__main__":
    main()
