import joblib
from utils import extract_features, is_phishing_by_tld, is_valid_url_format
from urllib.parse import urlparse
import socket
import os

# Load models
rf_model = joblib.load("ml/rf_model.pkl")
svm_model = joblib.load("ml/svm_model.pkl")

# Safe extension → country mapping
EXTENSION_COUNTRY_MAP = {
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

# ✅ Check if domain resolves (is live)
def domain_exists(url):
    try:
        domain = urlparse(url).netloc or urlparse(url).path
        socket.gethostbyname(domain)
        return True
    except Exception:
        return False

# ✅ Check if domain is blocked
def is_blocked(domain):
    if not os.path.exists("blocked_domains.txt"):
        return False
    with open("blocked_domains.txt", "r") as f:
        blocked = [line.strip().lower() for line in f.readlines()]
        return domain in blocked

# ✅ Main Prediction Logic
def predict_url(url):
    url = url.strip().lower()

    if not is_valid_url_format(url):
        return "❌ Undefined URL – Please provide a valid URL."

    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path

    # ✅ 1. Check if already blocked
    if is_blocked(domain):
        return "🚫 Already Blocked (Admin Blocked)"

    # ✅ 2. Check known safe extensions
    for ext, country in EXTENSION_COUNTRY_MAP.items():
        if domain.endswith(ext):
            if domain_exists(url):
                return f"✅ Safe ({ext} → {country})"
            else:
                return f"🚨 Fraud (Dead Domain with Safe Extension: {ext} → {country})"

    # ✅ 3. ML + TLD-based fraud check for unknown extensions
    features = extract_features(url)
    rf_pred = rf_model.predict([features])[0]
    svm_pred = svm_model.predict([features])[0]
    tld_flag = is_phishing_by_tld(url)

    if rf_pred or svm_pred or tld_flag:
        return "🚨 Fraud (Unknown Extension)"
    else:
        return "✅ Safe (ML Model)"
