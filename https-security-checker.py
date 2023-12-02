import requests
from bs4 import BeautifulSoup
import re
from colorama import Fore, Style

def analyze_url(url):
    # Sprawdzenie, czy URL zawiera potencjalnie niebezpieczne znaki
    dangerous_characters = re.findall(r'[\'"<>;=&]', url)
    if dangerous_characters:
        print(Fore.RED + "[-] Potentially dangerous characters found in the URL." + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "[+] URL seems safe from dangerous characters." + Style.RESET_ALL)

def analyze_forms(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        forms = soup.find_all('form')
        if forms:
            print(Fore.GREEN + "[+] Forms found on the page." + Style.RESET_ALL)
            # Tutaj możesz dodać kod analizujący pola formularza
        else:
            print(Fore.YELLOW + "[-] No forms found on the page." + Style.RESET_ALL)

    except requests.exceptions.RequestException as e:
        print(f"[-] Unable to analyze forms: {e}")

def check_sql_injection_vulnerability(url):
    try:
        response = requests.get(url)
        response.raise_for_status()

        if re.search(r'\b(UNION|OR|AND)\b', response.text, re.IGNORECASE):
            print(Fore.RED + "[-] Possible SQL Injection Vulnerability detected." + Style.RESET_ALL)
        else:
            print(Fore.GREEN + "[+] No SQL Injection Vulnerability found." + Style.RESET_ALL)

    except requests.exceptions.RequestException as e:
        print(f"[-] Unable to check for SQL Injection Vulnerability: {e}")

def check_database_leaks(url):
    # Tutaj możesz umieścić kod do sprawdzania wycieków baz danych
    pass

def check_brute_force_attack(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        login_form = soup.find('form', {'action': True, 'method': True})
        if login_form:
            print(Fore.GREEN + "[+] Login form found." + Style.RESET_ALL)
            # Tutaj możesz dodać kod sprawdzający potencjalne ataki brute force
        else:
            print(Fore.YELLOW + "[-] No login form found on the page." + Style.RESET_ALL)

    except requests.exceptions.RequestException as e:
        print(f"[-] Unable to check for brute force attack: {e}")

def check_ddos_attack(url):
    # Tutaj możesz umieścić kod do sprawdzania ataków DDoS
    pass

def check_security(url):
    analyze_url(url)
    analyze_forms(url)
    check_sql_injection_vulnerability(url)
    check_database_leaks(url)
    check_brute_force_attack(url)
    check_ddos_attack(url)

if __name__ == "__main__":
    print(Fore.BLUE + "[+] This program has been created for educational purposes and security testing only." + Style.RESET_ALL)
    url = input("Enter the website URL: ")
    check_security(url)
