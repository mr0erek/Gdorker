import requests, random, concurrent.futures, os, base64, json, re, contextlib, argparse, sys, time, readline
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
from urllib.parse import urlparse
from multiprocessing import Pool
from functools import partial
#from fake_useragent import UserAgent
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
VERSION = "2"

#################
# DEFAULT DORKS #
#################

INURL = [
"inurl:admin", 
"inurl:login", 
"inurl:adminlogin", 
"inurl:cplogin", 
"inurl:weblogin", 
"inurl:quicklogin", 
"inurl:wp-admin", 
"inurl:wp-login", 
"inurl:portal", 
"inurl:userportal", 
"inurl:loginpanel", 
"inurl:memberlogin", 
"inurl:remote", 
"inurl:dashboard", 
"inurl:auth", 
"inurl:exchange", 
"inurl:ForgotPassword", 
"inurl:test", 
"inurl:.git", 
"inurl:backup"
"index%20of:id_rsa%20id_rsa.pub",
]

FILETYPE = [
"filetype:doc", 
"filetype:dot", 
"filetype:docm", 
"filetype:docx", 
"filetype:dotx", 
"filetype:xls", 
"filetype:xlsm", 
"filetype:xlsx", 
"filetype:ppt", 
"filetype:pptx", 
"filetype:mdb", 
"filetype:pdf", 
"filetype:sql", 
"filetype:txt", 
"filetype:rtf", 
"filetype:csv", 
"filetype:xml", 
"filetype:conf", 
"filetype:dat", 
"filetype:ini", 
"filetype:log",  
"filetype:py", 
"filetype:html", 
"filetype:sh", 
"filetype:odt", 
"filetype:key", 
"filetype:sign", 
"filetype:md", 
"filetype:old", 
"filetype:bin", 
"filetype:cer", 
"filetype:crt", 
"filetype:pfx", 
"filetype:crl", 
"filetype:crs", 
"filetype:der", 
"filetype:pages", 
"filetype:keynote", 
"filetype:numbers", 
"filetype:odt", 
"filetype:ods",
"filetype:odp", 
"filetype:odg"
]

INTITLE = [
"intitle:%22index%20of%22%20%22parent%20directory%22", 
"intitle:%22index%20of%22%20%22DCIM%22", 
"intitle:%22index%20of%22%20%22ftp%22", 
"intitle:%22index%20of%22%20%22backup%22", 
"intitle:%22index%20of%22%20%22mail%22", 
"intitle:%22index%20of%22%20%22password%22", 
"intitle:%22index%20of%22%20%22pub%22", 
"intitle:%22index%20of%22%20%22.git%22", 
"intitle:%22index%20of%22%20%22log%22", 
"intitle:%22index%20of%22%20%22src%22", 
"intitle:%22index%20of%22%20%22env%22", 
"intitle:%22index%20of%22%20%22.env%22", 
"intitle:%22index%20of%22%20%22.sql%22", 
"intitle:%22index%20of%22%20%22api%22", 
"intitle:%22index%20of%22%20%22venv%22", 
"intitle:%22index%20of%22%20%admin%22"
]

######################################
# PROXY LOADER Via Given Github Repo # ~ Thanks to @SpeedX only for proxy!
######################################
def load_file_content(repo_owner, repo_name, file_path, access_token=None):
    url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/contents/{file_path}"
    headers = {}
    if access_token:
        headers['Authorization'] = f"Bearer {access_token}"

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        file_info = response.json()
        if 'content' in file_info:
            file_content = base64.b64decode(file_info['content']).decode('utf-8')
            return file_content
        else:
            return "No content found for the file."
    else:
        return f"Failed to fetch file content. Status code: {response.status_code}"

##########################
# Cache Saving/reloading # ~ Save's list of proxies into file for later usage [Duration : 24hr]
##########################

def save_cache(content, last_checked_time, JSON_FILE):
    cache_data = {
        "content": content,
        "last_checked_time": last_checked_time.isoformat()
    }
    with open(JSON_FILE, "w") as cache_file:
        json.dump(cache_data, cache_file)

def load_cache(JSON_FILE): 
    try:
        with open(JSON_FILE, "r") as cache_file:
            cache_data = json.load(cache_file)
            last_checked_time = datetime.fromisoformat(cache_data["last_checked_time"])
            return cache_data["content"], last_checked_time
    except FileNotFoundError:
        return None, None

##############
# Proxy Core #
##############

def UP_PROXIES(): 
    repo_owner = "TheSpeedX" 
    repo_name = "PROXY-List" 
    file_path = "http.txt"
    access_token = None  # Optional, if the repository is private  
    JSON_FILE = "cache.json" 
    cached_content, last_checked_time = load_cache(JSON_FILE) # Load cached content and last checked time 
    # Check if it's been less than 24 hours since last checked
    if last_checked_time and datetime.now() - last_checked_time < timedelta(days=0.5):
        current_dattime = datetime.now().strftime("%d%m%y%H%M%s")
        file_content = cached_content 
        time_difference = timedelta(days=1) - (datetime.now() - last_checked_time) 
        remaining_hours = time_difference.total_seconds() / 3600
        print(f"Using cached content until next check: {remaining_hours:.2f} hours...")
    else:
        print("Fetching updated content...")
        file_content = load_file_content(repo_owner, repo_name, file_path, access_token)
        if cached_content != file_content:
            print("Content updated. Saving to cache...")
            os.system(f"rm {JSON_FILE}")
            save_cache(file_content, datetime.now(), JSON_FILE) 
    proxy = []
    for line in file_content.split('\n'): 
        proxy.append(line.strip())  
    return proxy

##############
# Proxy Test # ~ Checks for Proxy, Weather it is working or not
##############

def test_proxy(ip, domain):
    #print(ip, domain)
    proxies = {
        "http": f"http://{ip}",
        "https": f"http://{ip}",
    }
    with contextlib.suppress(requests.RequestException):
        response = requests.get(f"http://{domain}", proxies=proxies, timeout=5, verify=True)
        #print(response.status_code, response)
        if response.status_code >= 200 and response.status_code < 300:
            return True
    return False

################
# File Sorting # ~ File Content loads and return it as List/array
################

def SortFileCore(files_):
    # Open the file in read mode
    with open(files_, 'r') as file:
     # Read all lines from the file
     lines = file.readlines()
     # Strip any surrounding whitespace or newline characters from each line
     Slist = [line.strip() for line in lines]
    return Slist

#######################
# ProxyChanging Logic #
#######################
def Proxychanger(proxy_list):
    proxy = random.choice(proxy_list)
    proxies = {
    'http' : proxy,
    'https' : proxy
    }
    session = requests.Session()
    session.proxies.update(proxies)
    return proxy

################
# Result Logic #
################
def Search_result(processes, target, pages) -> None:
    try:
        with Pool(int(processes)) as p:
            result = p.map(target, range(int(pages)))
        pg = 1
        if len(result[0]) == 0:
            print(f"{RED}[!]{WHITE} No result found")
        else:
            print(f"{BLUE}[{WHITE}+{BLUE}]{WHITE} Listing Sites...{GREEN}\n")

        for single_array in result:
            for counter, uri in enumerate(single_array):
                if counter == 0:
                    print(f"=========[PAGE : {pg}]=========\n")
                    pg += 1
                else:
                    pass
                print(f"[{counter + 1}] | {uri}")
                time.sleep(0.01) 
            print()
    except Exception as e:
         print(f"{RED}[!]{YELLOW} An runtime error occur, Reason:{WHITE}\n{e}")
         exit()    

##########################
# Core - Searching Logic #
##########################
def querysearch(query, pages):
    params = { 'q': query, 'start': pages * 10 }
    base_url = 'https://www.google.com/search' if engine == 'google' else 'https://www.bing.com/search'
    # ua = UserAgent()
    # random_ua = ua.random
    # print(random_ua)
    resp = requests.get(base_url, params=params, headers={'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:71.0) Gecko/20100101 Firefox/71.0'})
    soup = BeautifulSoup(resp.text, 'html.parser')
    links = soup.findAll("div", { "class" : "yuRUbf" }) if engine == 'google' else soup.findAll('cite')
    result = []
    for link in links:
        if engine.lower() == 'google':
            result.append(link.find('a').get('href'))
        elif engine.lower() == 'bing':
            result.append(link.text)
        else:
            print(f"Kindly Choose You Search engine Before Dorking...\n")
            exit()
    return result

#########################
# Logic for Dork Search #
#########################
def dork_core(sites, dork_list) -> None:
    proxy_list = UP_PROXIES()
    cookies = {
    "CONSENT": "YES+srp.gws-20211028-0-RC2.es+FX+330"
    }
    for search_query in sites:
        PROXY = Proxychanger(proxy_list)
        print(f"{GREEN}[{WHITE}+{GREEN}] {YELLOW}Proxy : {WHITE}{PROXY}")
        time.sleep(0.5)
        print(f"{GREEN}[{WHITE}+{GREEN}] {YELLOW}User-Agent : {WHITE}Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:71.0) Gecko/20100101 Firefox/71.0")
        for dork in dork_list:
            print(f"{GREEN}[{WHITE}+{GREEN}] {YELLOW}G-dork : {dork}{WHITE}")
            print(f"{GREEN}[{WHITE}+{GREEN}] {YELLOW}checking for  : {WHITE}site:{search_query} {dork}\n")
            query = f"site:{search_query} {dork}"
            print("URL :", search_query, f"\n")
            target = partial(querysearch, query)
            Search_result(processes, target, pages)

###########################
# Logic for Simple Search #
###########################
def query_core(query, pages, processes) -> None:
    proxy_list = UP_PROXIES()
    cookies = {
    "CONSENT": "YES+srp.gws-20211028-0-RC2.es+FX+330"
    }
    PROXY = Proxychanger(proxy_list)
    print(f"{GREEN}[{WHITE}+{GREEN}] {YELLOW}Proxy : {WHITE}{PROXY}")
    time.sleep(0.5)
    print(f"{GREEN}[{WHITE}+{GREEN}] {YELLOW}User-Agent : {WHITE}Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:71.0) Gecko/20100101 Firefox/71.0")
    target = partial(querysearch, query)  
    Search_result(processes, target, pages)

#####################
# URL/QUERY Checks #
####################

def is_url(string):
    # Define a regular expression for a basic URL structure
    url_regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' # domain...
        r'localhost|' # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|' # ...or ipv4
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)' # ...or ipv6
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    # Use the regex to check if the string matches the URL pattern
    return re.match(url_regex, string) is not None

##################
# Auto Completer # 
##################

def completer(text, state):
    # Get the list of files and directories in the current directory
    options = [name for name in os.listdir('.') if name.startswith(text)]
    # Return the state-th completion (None if out of range)
    try:
        return options[state]
    except IndexError:
        return None

def sub_condition(sites) -> None:
    if args.dork is True and type(args.dork) is not str:
        dork_list = []
        dork_list.extend(FILETYPE + INURL + INTITLE)
        dork_core(sites, dork_list)
    elif type(args.dork) is str:
        if os.path.exists(args.dork):
            dork_list = SortFileCore(args.dork)
            dork_core(sites, dork_list)
        else: 
            print(f"{YELLOW}[!] Mentioned File : {WHITE}{args.dork} does not exist\n")
            exit()
    else:
        sites = None
        sites = query
        query_core(sites, pages, processes)
 
###############
# Main Banner # 
###############
def banner():
    print(f'''{GREEN}
8""""8      8""""8                                 
8    "      8    8 eeeee eeeee  e   e  eeee eeeee  
8e          8e   8 8  88 8   8  8   8  8    8   8  
88  ee eeee 88   8 8   8 8eee8e 8eee8e 8eee 8eee8e 
88   8      88   8 8   8 88   8 88   8 88   88   8 
88eee8      88eee8 8eee8 88   8 88   8 88ee 88   8 {YELLOW}v{VERSION}{WHITE}  
                                                  {YELLOW}by @e343io) {WHITE}
{WHITE}---------------------------------------------------------------------
#{BLUE} This Tool is not claiming to be a perfect, google                  {WHITE}#
#{BLUE} dorking tool,I tried to make it work in rush,                      {WHITE}#
#{BLUE} So any idea or bugfix related query - just rebuild and contribute. {WHITE}#
{WHITE}---------------------------------------------------------------------
{YELLOW}[NOTE]: Use fastest VPN to avoid IP leak, proxy is not working for now.
''')

try:
    banner()
#############################
# readline for autocomplete # 
#############################
    
    readline.set_completer(completer)
    readline.parse_and_bind("tab: complete")
    
#################
# CLI arguments #
#################

    parser = argparse.ArgumentParser(description="Google Dorking Tool")
    parser.add_argument("-s", "--search", dest="search", help="Site/Query to search", type=str)
    parser.add_argument("-d", "--dork", dest="dork", help="To Enable Dork Search, -d <files> for coustom Dorking.", nargs='?', const=True, default=False)
    parser.add_argument("-e", "--engine", dest="engine", help="Choose your search Google/Bing", type=str)
    parser.add_argument("-p", "--pages", dest="pages", help="Specify the Number of Pages (Default: 1)", type=int)
    parser.add_argument("-P", "--process", dest="processes", help="Specify the Number of Processes (Default: 2)", type=int)
    parser.add_argument("-sl", "--site-list", dest="sitelist", help="Add your Site list file", type=str)
    args = parser.parse_args()
    argeng = args.engine
    #list_ans = 0
##################################
# Condition for engine selection #
##################################

    if not argeng or argeng == None:
        user_inp2 = input(f"{CYAN}Choose Search Engine, {YELLOW}(Google/Bing)\n{CYAN}~>{WHITE} ")
        if user_inp2.lower() == 'bing':
            engine = 'bing'
        elif user_inp2.lower() == 'google':
        	engine = 'google'
        else:
            engine = 'google'
            print(f"{YELLOW}[!] Using a Default search engine : {WHITE}{engine.upper()}...")
            time.sleep(2)
    elif argeng.lower() == 'google':
        engine = 'google'
    elif argeng.lower() == 'bing':
        engine = 'bing'
    else:
            print("Mention Engine (Google/Bing)...")
            exit()

##########################################  
# Condition for page and processes count #
##########################################

    if not args.pages:
        pages = 1
    else:
        pages = args.pages
        print(pages)

    if not args.processes:
        processes = 2
    else:
        processes = args.processes
        print(processes)

#################################
# URL/QUERY assigning condition #
#################################

    if not args.search and not args.sitelist:
        query = input(f"{CYAN}Enter Your SearcH QuerY/URL:\n~>{WHITE} ")
        sites = [f"{query}"]
        sub_condition(sites)
    elif args.search and type(args.search) is str:
        query = args.search
        sites = [f"{query}"]
        sub_condition(sites)
    elif args.search and type(args.search) is str and args.search != "":
        query = args.search
        sites = [f"{query}"]
        sub_condition(sites)
    elif type(args.sitelist) is str and args.sitelist != "":
        if os.path.exists(args.sitelist):
            sites = SortFileCore(args.sitelist)
            sub_condition(sites)
        else:
            print(f"{YELLOW}[!] Mentioned File : {WHITE}{args.sitelist} does not exist\n")
            exit()
    else:
        print(f"Kindly Mention all parameters correctly.")
        exit()

#add a function to run tool
except(EOFError, KeyboardInterrupt):
	print(f"\nThanks for using Gdorker.")
	exit()
