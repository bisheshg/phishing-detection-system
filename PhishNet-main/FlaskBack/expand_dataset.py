import pandas as pd
import requests
from bs4 import BeautifulSoup
import whois
from urllib.parse import urlparse
import re
import time
from datetime import date
import ipaddress

# ==================== FEATURE EXTRACTION CLASS ====================
class FeatureExtraction:
    def __init__(self, url):
        self.features = []
        self.url = url.strip()
        self.domain = ""
        self.whois_response = None
        self.urlparse = None
        self.response = None
        self.soup = None

        # Fetch page
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            self.response = requests.get(self.url, timeout=10, headers=headers, allow_redirects=True)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except:
            pass

        # Parse URL
        try:
            self.urlparse = urlparse(self.url)
            self.domain = self.urlparse.netloc
            if self.domain.startswith('www.'):
                self.domain = self.domain[4:]
        except:
            pass

        # WHOIS lookup
        try:
            self.whois_response = whois.whois(self.domain)
        except:
            pass

        # Extract 30 features in correct order
        self.features = [
            self.UsingIp(),
            self.longUrl(),
            self.shortUrl(),
            self.symbol(),
            self.redirecting(),
            self.prefixSuffix(),
            self.SubDomains(),
            self.Hppts(),
            self.DomainRegLen(),
            self.Favicon(),
            self.NonStdPort(),
            self.HTTPSDomainURL(),
            self.RequestURL(),
            self.AnchorURL(),
            self.LinksInScriptTags(),
            self.ServerFormHandler(),
            self.InfoEmail(),
            self.AbnormalURL(),
            self.WebsiteForwarding(),
            self.StatusBarCust(),
            self.DisableRightClick(),
            self.UsingPopupWindow(),
            self.IframeRedirection(),
            self.AgeofDomain(),
            self.DNSRecording(),
            self.WebsiteTraffic(),
            self.PageRank(),
            self.GoogleIndex(),
            self.LinksPointingToPage(),
            self.StatsReport()
        ]

    def UsingIp(self):
        try:
            ipaddress.ip_address(self.domain)
            return -1
        except:
            return 1

    def longUrl(self):
        if len(self.url) < 54: return 1
        if len(self.url) <= 75: return 0
        return -1

    def shortUrl(self):
        pattern = r'bit\.ly|goo\.gl|shorl\.com|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net'
        return -1 if re.search(pattern, self.url.lower()) else 1

    def symbol(self):
        return -1 if '@' in self.url else 1

    def redirecting(self):
        return -1 if self.url.rfind('//') > 6 else 1

    def prefixSuffix(self):
        return -1 if '-' in self.domain else 1

    def SubDomains(self):
        dots = self.domain.count('.')
        if dots == 1: return 1
        if dots == 2: return 0
        return -1

    def Hppts(self):
        return 1 if self.urlparse.scheme == 'https' else -1

    def DomainRegLen(self):
        if not self.whois_response: return -1
        try:
            exp = self.whois_response.expiration_date
            cre = self.whois_response.creation_date
            if isinstance(exp, list): exp = exp[0]
            if isinstance(cre, list): cre = cre[0]
            if exp and cre:
                months = (exp.year - cre.year) * 12 + (exp.month - cre.month)
                return 1 if months >= 12 else -1
        except: pass
        return -1

    def Favicon(self):
        if not self.soup: return 1
        fav = self.soup.find("link", rel=re.compile("icon", re.I))
        if fav and 'href' in fav.attrs:
            href = fav['href']
            return 1 if self.domain in href or href.startswith('/') else -1
        return 1

    def NonStdPort(self):
        return -1 if ':' in self.domain and self.domain.split(':')[1] not in ['80', '443'] else 1

    def HTTPSDomainURL(self):
        return -1 if 'https' in self.domain else 1

    def RequestURL(self):
        if not self.soup: return -1
        total, same = 0, 0
        for tag in self.soup.find_all(['img', 'audio', 'video', 'embed', 'iframe'], src=True):
            total += 1
            src = tag['src']
            if self.domain in src or src.startswith('/'): same += 1
        if total == 0: return 1
        perc = same / total
        if perc < 0.22: return 1
        if perc < 0.61: return 0
        return -1

    def AnchorURL(self):
        if not self.soup: return -1
        total, unsafe = 0, 0
        for a in self.soup.find_all('a', href=True):
            total += 1
            href = a['href'].lower()
            if href.startswith(('#', 'javascript:', 'mailto:')) or not (self.domain in href or href.startswith('/')):
                unsafe += 1
        if total == 0: return -1
        perc = unsafe / total
        if perc < 0.31: return 1
        if perc < 0.67: return 0
        return -1

    def LinksInScriptTags(self):
        if not self.soup: return -1
        total, same = 0, 0
        tags = self.soup.find_all(['link', 'script'], href=True) + self.soup.find_all('script', src=True)
        for tag in tags:
            total += 1
            attr = tag.get('href') or tag.get('src')
            if attr and (self.domain in attr or attr.startswith('/')): same += 1
        if total == 0: return 1
        perc = same / total
        if perc < 0.17: return 1
        if perc < 0.81: return 0
        return -1

    def ServerFormHandler(self):
        if not self.soup: return -1
        forms = self.soup.find_all('form', action=True)
        if not forms: return 1
        for form in forms:
            action = form['action'].lower()
            if action in ['', 'about:blank']: return -1
            if not (self.domain in action or action.startswith('/')): return 0
        return 1

    def InfoEmail(self):
        if not self.soup: return 1
        return -1 if re.search(r'mail\(\)|mailto:', str(self.soup)) else 1

    def AbnormalURL(self):
        return -1 if not self.whois_response else 1

    def WebsiteForwarding(self):
        if not self.response: return -1
        n = len(self.response.history)
        if n <= 1: return 1
        if n <= 4: return 0
        return -1

    def StatusBarCust(self):
        if not self.soup: return 1
        return -1 if re.search(r'onmouseover.*window\.status', str(self.soup)) else 1

    def DisableRightClick(self):
        if not self.soup: return 1
        return -1 if re.search(r'event\.button\s*==\s*2', str(self.soup)) else 1

    def UsingPopupWindow(self):
        if not self.soup: return 1
        return -1 if 'alert(' in str(self.soup) else 1

    def IframeRedirection(self):
        if not self.soup: return 1
        return -1 if self.soup.find('iframe', {'frameborder': re.compile("0", re.I)}) else 1

    def AgeofDomain(self):
        if not self.whois_response: return -1
        try:
            cre = self.whois_response.creation_date
            if isinstance(cre, list): cre = cre[0]
            months = (date.today() - cre.date()).days // 30
            return 1 if months >= 6 else -1
        except: return -1

    def DNSRecording(self):
        return self.AgeofDomain()

    def WebsiteTraffic(self):
        return -1  # Alexa defunct

    def PageRank(self):
        return -1

    def GoogleIndex(self):
        return 1

    def LinksPointingToPage(self):
        return 0

    def StatsReport(self):
        return 1

    def getFeaturesList(self):
        return self.features

# ==================== MAIN SCRIPT ====================

# Load original dataset (this ensures all 11,055 rows are included)
original_csv = 'Phishing.csv'
original_df = pd.read_csv(original_csv)
columns = original_df.columns.tolist()  # Includes Index, 30 features, class

print(f"Original dataset loaded: {len(original_df)} rows")

# Fetch fresh phishing URLs from OpenPhish
print("Fetching latest phishing URLs from OpenPhish...")
try:
    feed = requests.get('https://openphish.com/feed.txt', timeout=15)
    phishing_urls = [line.strip() for line in feed.text.splitlines() if line.strip() and line.startswith('http')]
    print(f"Fetched {len(phishing_urls)} phishing URLs")
except Exception as e:
    print(f"Failed to fetch feed: {e}")
    print("Using fallback list...")
    phishing_urls = [
        "https://shortlink.st/8V-Ob7dw",
        "https://gemniixilogiem.gitbook.io/us/",
        "https://roblox.com.ge/users/2392720665/profile",
        # Add more if needed
    ]

# Legitimate URLs (top trusted sites)
legit_urls = [
    "https://google.com", "https://youtube.com", "https://facebook.com", "https://amazon.com",
    "https://netflix.com", "https://microsoft.com", "https://apple.com", "https://instagram.com",
    "https://twitter.com", "https://linkedin.com", "https://github.com", "https://wikipedia.org"
]

def process_urls(url_list, label):
    rows = []
    for url in url_list:
        try:
            extractor = FeatureExtraction(url)
            features = extractor.getFeaturesList()
            if len(features) == 30:
                rows.append(features + [label])
                print(f"Success: {url} -> {'Phishing' if label == -1 else 'Legitimate'}")
            else:
                print(f"Failed: {url} - only {len(features)} features")
        except Exception as e:
            print(f"Error: {url} -> {e}")
        time.sleep(0.5)  # Be gentle on servers
    return rows

print("\nProcessing phishing URLs...")
phishing_rows = process_urls(phishing_urls[:200], -1)  # Limit to 200 to avoid long run

print("\nProcessing legitimate URLs...")
legit_rows = process_urls(legit_urls, 1)

# Combine: original features + class + new rows
new_features_class = phishing_rows + legit_rows
if new_features_class:
    new_df = pd.DataFrame(new_features_class, columns=columns[1:])  # Exclude Index
    combined = pd.concat([original_df[columns[1:]], new_df], ignore_index=True)
else:
    combined = original_df[columns[1:]]

# Deduplicate by features + class
combined.drop_duplicates(inplace=True)

# Add new Index
combined.insert(0, 'Index', range(len(combined)))

# Save
combined.to_csv('Expanded_Phishing.csv', index=False)

print(f"\nFINAL SUCCESS!")
print(f"Total rows: {len(combined)}")
print(f"Phishing (-1): { (combined['class'] == -1).sum() }")
print(f"Legitimate (1): { (combined['class'] == 1).sum() }")
print("Saved to Expanded_Phishing.csv")