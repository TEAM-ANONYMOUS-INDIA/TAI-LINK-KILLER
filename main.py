import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re
from colorama import Fore, Style, init

# Initialize colorama for CLI colors
init(autoreset=True)

# Stylish Hacker Banner with Copyright
BANNER = f"""{Fore.RED}
███████╗██╗░░░░░██╗██████╗░███████╗
██╔════╝██║░░░░░██║██╔══██╗██╔════╝
█████╗░░██║░░░░░██║██████╦╝█████╗░░
██╔══╝░░██║░░░░░██║██╔══██╗██╔══╝░░
██║░░░░░███████╗██║██████╦╝███████╗
╚═╝░░░░░╚══════╝╚═╝╚═════╝░╚══════╝ {Style.RESET_ALL}
{Fore.YELLOW}  🚀 Ultimate Website Security Scanner 🚀  
   {Fore.GREEN}© TEAM ANONYMOUS INDIA{Style.RESET_ALL}
"""

# **Extended Admin Panel Paths (Inspired by DH HackBar & OSINT Tools)**
ADMIN_PATHS = [
    "admin/", "admin.php", "wp-admin/", "dashboard/", "cpanel/", "webmail/",
    "phpmyadmin/", "config.php", "admin-console/", "moderator/", "secureadmin/",
    "administrator/", "admin123/", "superadmin/", "admin-panel/", "controlpanel/",
    "backend/", "manager/", "management/", "admin_area/", "adm/", "system/",
    "admin2/", "secretadmin/", "rootadmin/", "useradmin/", "admin_login/",
    "authadmin/", "securepanel/", "config_admin/", "cmsadmin/", "moderation/",
    "wp-admin/admin.php", "wp-login.php", "secure-login/", "admincontrol/",
    "support/login/", "auth/", "myadmin/", "sysadmin/", "serveradmin/"
]

# Vulnerability patterns to check for common attack vectors
VULNERABILITY_PATTERNS = [
    r"\?id=\d+",  # SQL Injection (numeric ID)
    r"<script.*?>.*?</script>",  # XSS (Cross-site scripting)
    r"\.\./",  # Directory Traversal
    r"\.env",  # Unsecured .env file
    r"\.git",  # Git directory or files
    r"\.bak",  # Backup files
    r"\?page=\d+"  # SQL Injection (generic page parameter)
]

def request_url(url, allow_redirects=True):
    """Make a request with error handling."""
    try:
        response = requests.get(url, timeout=10, allow_redirects=allow_redirects)
        return response
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[-] Error: {e}{Style.RESET_ALL}")
        return None

def extract_links(url):
    """Extract all links from a given website."""
    response = request_url(url)
    if response:
        soup = BeautifulSoup(response.text, "html.parser")
        links = set()
        
        # Find all <a> tags and extract the href attribute (links)
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            full_url = urljoin(url, href)  # Convert relative links to absolute
            links.add(full_url)

        return links
    return set()

def google_dork_finder(domain):
    """Generate Google Dorks for security research."""
    dorks = [
        f"site:{domain} inurl:admin",
        f"site:{domain} inurl:login",
        f"site:{domain} intitle:index of",
        f"site:{domain} inurl:php?id=",
        f"site:{domain} ext:sql | ext:db | ext:log",
        f"site:{domain} inurl:wp-content | inurl:wp-admin",
        f"site:{domain} inurl:.env",
        f"site:{domain} ext:txt inurl:robots.txt",
        f"site:{domain} intext:'SQL syntax'",
        f"site:{domain} inurl:backup | inurl:old | inurl:archive"
    ]
    print(f"\n{Fore.MAGENTA}🔍 Google Dorks for {domain}:\n{Style.RESET_ALL}")
    for i, dork in enumerate(dorks, start=1):
        print(f"{Fore.YELLOW}{i}. {Fore.CYAN}https://www.google.com/search?q={dork}{Style.RESET_ALL}")

def admin_panel_finder(url):
    """Scan for admin panels on the target website."""
    print(f"\n{Fore.BLUE}🔎 Scanning for Admin Panels...\n{Style.RESET_ALL}")
    for path in ADMIN_PATHS:
        full_url = urljoin(url, path)
        response = request_url(full_url)
        if response:
            if response.status_code == 200:
                print(f"{Fore.GREEN}[+] Found Admin Panel: {full_url}{Style.RESET_ALL}")
            elif response.status_code in [403, 401]:
                print(f"{Fore.YELLOW}[!] Restricted Access: {full_url}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] Not Found: {full_url}{Style.RESET_ALL}")

def waf_detector(url):
    """Detect Web Application Firewall (WAF)"""
    response = request_url(url)
    if response:
        headers = response.headers
        waf_signatures = ["cloudflare", "sucuri", "imperva", "akamai", "barracuda", "f5", "citrix"]
        for waf in waf_signatures:
            if waf.lower() in headers.get("Server", "").lower():
                print(f"{Fore.YELLOW}[!] WAF Detected: {waf.upper()}{Style.RESET_ALL}")
                return
        print(f"{Fore.GREEN}[+] No WAF Detected{Style.RESET_ALL}")

def no_redirect_finder(url):
    """Finds pages that do not properly handle redirects."""
    response = request_url(url, allow_redirects=False)
    if response:
        if 300 <= response.status_code < 400:
            print(f"{Fore.YELLOW}[!] Redirect Found: {url} -> {response.headers.get('Location')}{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[+] No Redirect Detected: {url}{Style.RESET_ALL}")

def header_analyzer(url):
    """Analyze HTTP headers for security misconfigurations."""
    response = request_url(url)
    if response:
        headers = response.headers
        print(f"\n{Fore.BLUE}🔎 Security Header Analysis:\n{Style.RESET_ALL}")
        for header, value in headers.items():
            print(f"{Fore.YELLOW}{header}: {Fore.CYAN}{value}{Style.RESET_ALL}")

def vulnerability_finder(links):
    """Check extracted links for common vulnerabilities."""
    print(f"\n{Fore.RED}⚠️ Checking for Vulnerabilities...\n{Style.RESET_ALL}")
    for link in links:
        found_vulnerability = False
        for pattern in VULNERABILITY_PATTERNS:
            if re.search(pattern, link):
                print(f"{Fore.YELLOW}[!] Potential Vulnerability Found: {link} (Pattern: {pattern}){Style.RESET_ALL}")
                found_vulnerability = True
                break  # Stop once a vulnerability pattern is found for the link
        if found_vulnerability == False:
            continue  # Skip if no vulnerability is found for this link

if __name__ == "__main__":
    print(BANNER)
    target_url = input(f"{Fore.MAGENTA}Enter the website URL: {Style.RESET_ALL}").strip()
    
    # Extract all links from the website
    extracted_links = extract_links(target_url)
    if extracted_links:
        print(f"\n{Fore.GREEN}[+] Extracted {len(extracted_links)} Links:{Style.RESET_ALL}")
        for idx, link in enumerate(extracted_links, start=1):
            print(f"{Fore.CYAN}{idx}. {Fore.YELLOW}{link}{Style.RESET_ALL}")
        # Check for vulnerabilities only in the extracted links
        vulnerability_finder(extracted_links)

    google_dork_finder(target_url)
    waf_detector(target_url)
    admin_panel_finder(target_url)
    no_redirect_finder(target_url)
    header_analyzer(target_url)
