import re
import socket
from urllib.parse import urlparse
from datetime import datetime
import whois
import os
import csv

# ✅ Safe TLD → Country Mapping
SAFE_EXTENSION_COUNTRIES = {
        '.com': 'Global',
    '.org': 'Non-Profit',
    '.net': 'Network Infra',
    '.edu': 'Education',
    '.gov': 'Government',
    '.in': 'India',
    '.ac.in': 'India (Academic)',
    '.us': 'USA',
    '.uk': 'United Kingdom',
    '.au': 'Australia',
    '.ca': 'Canada',
    '.de': 'Germany',
    '.fr': 'France',
    '.jp': 'Japan',
    '.cn': 'China',
    '.kr': 'South Korea',
    '.ru': 'Russia',
    '.br': 'Brazil',
    '.za': 'South Africa',
    '.it': 'Italy',
    '.es': 'Spain',
    '.nl': 'Netherlands',
    '.ch': 'Switzerland',
    '.se': 'Sweden',
    '.no': 'Norway',
    '.fi': 'Finland',
    '.dk': 'Denmark',
    '.be': 'Belgium',
    '.sg': 'Singapore',
    '.my': 'Malaysia',
    '.id': 'Indonesia',
    '.nz': 'New Zealand',
    '.mx': 'Mexico',
    '.ar': 'Argentina',
    '.tr': 'Turkey',
    '.pk': 'Pakistan',
    '.bd': 'Bangladesh',
    '.lk': 'Sri Lanka',
    '.np': 'Nepal',
    '.ae': 'UAE',
    '.sa': 'Saudi Arabia',
    '.eg': 'Egypt',
    '.ng': 'Nigeria',
    '.ke': 'Kenya',
    '.dev': 'Developer (Google)',
    '.ai': 'AI / Anguilla',
    '.io': 'Tech / British Indian Ocean',
    '.co': 'Colombia / Startups',
    '.app': 'Google App Platform',
    '.tech': 'Technology',
    '.store': 'E-commerce',
    '.xyz': 'Generic / Startups',
    '.site': 'Generic / Web',
    '.online': 'Generic / Online',
    '.bio': 'Biotech / Personal',
    '.design': 'Design / Creative Industry',
    '.me': 'Personal / Montenegro',
    '.info': 'Information',
    '.tv': 'Media / Tuvalu',
    '.pro': 'Professionals',
    '.media': 'Media',
    '.news': 'News / Publications',
    '.agency': 'Agencies / Businesses',
    '.academy': 'Education / Learning',
    '.group': 'Organizations / Communities',
    '.today': 'News / Updates',
    '.center': 'Organizations / Services',
    '.capital': 'Finance / Investment',
    '.consulting': 'Business Consulting',
    '.company': 'Companies',
    '.finance': 'Financial Sector',
    '.support': 'Support Services',
    '.digital': 'Digital Services',
    '.tools': 'Online Tools',
    '.network': 'Network / Infrastructure',
    '.systems': 'IT / Infrastructure',
    '.solutions': 'Tech Solutions',
    '.ventures': 'Startups / Ventures',
}
SAFE_EXTENSIONS = SAFE_EXTENSION_COUNTRIES.keys()

# ✅ Validate if input looks like a URL
def is_valid_url_format(url):
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    return "." in domain and len(domain) > 3

# ✅ Extract domain from URL
def extract_domain(url):
    parsed = urlparse(url)
    return parsed.netloc or parsed.path

# ✅ Check if domain is resolvable (live)
def domain_exists(domain):
    try:
        socket.setdefaulttimeout(3)
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False

# ✅ Heuristic phishing detection based on unknown TLD and liveness
def is_phishing_by_tld(url):
    url = url.lower()
    for ext in SAFE_EXTENSIONS:
        if url.endswith(ext):
            return 0
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    return 0 if domain_exists(domain) else 1

# ✅ WHOIS Domain Age Checker
def check_whois(domain):
    try:
        data = whois.whois(domain)
        creation_date = data.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            age_days = (datetime.now() - creation_date).days
            return {"age_days": age_days, "valid": age_days > 180}
    except Exception as e:
        print(f"[WHOIS Error] {e}")
    return {"age_days": 0, "valid": False}

# ✅ Return country or usage of the domain extension
def get_country_by_extension(url):
    url = url.lower()
    for ext, country in SAFE_EXTENSION_COUNTRIES.items():
        if url.endswith(ext):
            return f"{ext} → {country}"
    return "Unknown"

# ✅ Extract ML features (8 total)
def extract_features(url):
    url = url.lower()
    parsed = urlparse(url)
    hostname = parsed.netloc or parsed.path
    return [
        len(url),
        int("https" in url),
        url.count('.'),
        int("@" in url),
        int("//" in url[8:]),
        int("-" in url),
        len(re.findall(r"\d", url)),
        is_phishing_by_tld(url)
    ]

# ✅ Blocklist Management
def is_blocked(domain):
    try:
        with open("blocked_domains.txt", "r") as file:
            return domain.strip() in [d.strip() for d in file.read().splitlines()]
    except FileNotFoundError:
        return False

def add_to_blocklist(domain):
    if not is_blocked(domain):
        with open("blocked_domains.txt", "a", encoding="utf-8") as file:
            file.write(domain.strip() + "\n")

def remove_from_blocklist(domain):
    try:
        with open("blocked_domains.txt", "r") as file:
            domains = file.read().splitlines()
        domains = [d for d in domains if d.strip() != domain.strip()]
        with open("blocked_domains.txt", "w") as file:
            for d in domains:
                file.write(d + "\n")
    except FileNotFoundError:
        pass

def read_blocked_domains():
    try:
        with open("blocked_domains.txt", "r") as file:
            return file.read().splitlines()
    except FileNotFoundError:
        return []

# ✅ Logging to CSV (UTF-8 Safe)
# In utils.py
def log_detection(url, result, user_email=None, filename='logs/logs.csv'):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = [now, url, result, user_email or 'Unknown']
    os.makedirs(os.path.dirname(filename), exist_ok=True)

    file_exists = os.path.exists(filename)
    with open(filename, 'a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["Timestamp", "URL", "Result", "User Email"])
        writer.writerow(log_entry)


# ✅ Dashboard Log Reader
def read_logs():
    logs = []
    try:
        with open("logs/logs.csv", "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) >= 3:
                    logs.append(row)
    except FileNotFoundError:
        pass
    return logs[::-1]  # Latest first

# ✅ Filter logs
def filter_logs(logs, filter_type):
    if filter_type == "safe":
        return [log for log in logs if "Safe" in log[2]]
    elif filter_type == "fraud":
        return [log for log in logs if "Fraud" in log[2] or "🚨" in log[2]]
    elif filter_type == "blocked":
        return [log for log in logs if "Blocked" in log[2] or "🚫" in log[2]]
    else:
        return logs


def get_blocked_domains():
    blocked_file = 'blocked_domains.txt'
    if not os.path.exists(blocked_file):
        return []
    with open(blocked_file, 'r') as f:
        return [line.strip() for line in f if line.strip()]
