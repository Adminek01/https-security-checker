import requests
from bs4 import BeautifulSoup
import ssl

def check_https_security(url):
    # Ignorowanie błędów certyfikatu SSL (tylko do celów testowych)
    ssl._create_default_https_context = ssl._create_unverified_context

    # Pobranie strony internetowej
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"[-] Unable to retrieve the website: {e}")
        return

    # Sprawdzenie certyfikatu SSL
    if not response.history and response.url.startswith("https"):
        print("[+] Website is using HTTPS")

        # Analiza HTML w celu znalezienia tagów meta związanych z bezpieczeństwem
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

    else:
        print("[-] Website is not using HTTPS")

if __name__ == "__main__":
    url = input("Enter the website URL: ")
    check_https_security(url)
