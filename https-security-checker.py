import requests
from bs4 import BeautifulSoup
import ssl

def check_https_security(url):
    ssl._create_default_https_context = ssl._create_unverified_context

    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"[-] Unable to retrieve the website: {e}")
        return

    if not response.history and response.url.startswith("https"):
        print("[+] Website is using HTTPS")

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

    else:
        print("[-] Website is not using HTTPS")

def check_dns_ip_leaks(url):
    # Tutaj możesz umieścić kod do sprawdzania wycieków DNS/IP
    pass

def check_database_leaks(url):
    # Tutaj możesz umieścić kod do sprawdzania wycieków baz danych
    pass

if __name__ == "__main__":
    url = input("Enter the website URL: ")
    check_https_security(url)
