import requests
from bs4 import BeautifulSoup
import ssl
import re

def check_website_security(url):
    ssl._create_default_https_context = ssl._create_unverified_context

    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"[-] Unable to retrieve the website: {e}")
        return

    if not response.history and response.url.startswith("https"):
        print("[+] Website is using HTTPS")
        print_detailed_info(response)

        soup = BeautifulSoup(response.text, 'html.parser')
        meta_tags = soup.find_all('meta')

        security_info = []
        for tag in meta_tags:
            if 'security' in tag.get('name', '').lower() or 'security' in tag.get('content', '').lower():
                security_info.append(tag)

        if security_info:
            print("[+] Security information found:")
            for tag in security_info:
                print(f"    - {tag}")
        else:
            print("[-] No security information found")

        # Sprawdzanie wycieków DNS/IP
        check_dns_ip_leaks(url)

        # Sprawdzanie wycieków baz danych
        check_database_leaks(url)

        # Sprawdzanie ataków brute force
        check_brute_force_attack(url)

        # Sprawdzanie podatności na SQL injection
        check_sql_injection_vulnerability(url)

    else:
        print("[-] Website is not using HTTPS")

def print_detailed_info(response):
    print("[+] Detailed Information:")
    print(f"    - Server: {response.headers.get('server', 'N/A')}")
    print(f"    - SSL Certificate: {response.headers.get('x-powered-by', 'N/A')}")
    print(f"    - Content Type: {response.headers.get('content-type', 'N/A')}")

def check_dns_ip_leaks(url):
    # Tutaj możesz umieścić kod do sprawdzania wycieków DNS/IP
    pass

def check_database_leaks(url):
    # Tutaj możesz umieścić kod do sprawdzania wycieków baz danych
    pass

def check_brute_force_attack(url):
    # Sprawdzanie formularza logowania i podejrzenie ataku brute force
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        login_form = soup.find('form', {'action': True, 'method': True})
        if login_form:
            print("[+] Login form found. Checking for potential brute force attack.")
            # Tutaj możesz dodać kod sprawdzający potencjalne ataki brute force
        else:
            print("[+] No login form found on the page.")

    except requests.exceptions.RequestException as e:
        print(f"[-] Unable to check for brute force attack: {e}")

def check_sql_injection_vulnerability(url):
    # Sprawdzanie podatności na SQL injection
    try:
        response = requests.get(url + "/?id=1' OR '1'='1'--")
        if 'error' in response.text.lower() or 'exception' in response.text.lower():
            print("[+] Possible SQL Injection Vulnerability detected.")
        else:
            print("[+] No SQL Injection Vulnerability found.")
    except requests.exceptions.RequestException as e:
        print(f"[-] Unable to check for SQL Injection Vulnerability: {e}")

if __name__ == "__main__":
    url = input("Enter the website URL: ")
    check_website_security(url)
