import socket
import aiohttp
from bs4 import BeautifulSoup
import asyncio
import subprocess
from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from fake_useragent import UserAgent
import json

# Definiowanie funkcji pomocniczych

def get_ip_from_domain(domain):
    """Pobiera adres IP z domeny"""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def scan_ports(ip, start, end):
    """Skanuje porty w podanym zakresie"""
    open_ports = []
    print(f"   Skanowanie portów {start}-{end}...", end=" ", flush=True)
    for port in range(start, end + 1):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        result = s.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        s.close()
    print("OK")
    return open_ports

async def test_website(url, session):
    """Testuje podstawowe informacje o stronie"""
    website_info = {}
    try:
        async with session.get(url, timeout=10, ssl=False) as response:
            website_info['status'] = response.status
            website_info['headers'] = dict(response.headers)
            website_info['content_length'] = len(await response.text())
            
            # Podstawowe testy bezpieczeństwa
            website_info['security_headers'] = check_security_headers(response.headers)
            
    except Exception as e:
        website_info['error'] = str(e)
    return website_info

def check_security_headers(headers):
    """Sprawdza obecność ważnych nagłówków bezpieczeństwa"""
    security_headers = {
        'X-Frame-Options': headers.get('X-Frame-Options'),
        'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
        'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
        'Content-Security-Policy': headers.get('Content-Security-Policy'),
        'X-XSS-Protection': headers.get('X-XSS-Protection')
    }
    return {k: v if v else 'Missing' for k, v in security_headers.items()}

async def test_xss(url, session):
    """Podstawowy test XSS"""
    test_payloads = [
        "<script>alert('XSS')</script>",
        "'\"><script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>"
    ]
    
    results = []
    for payload in test_payloads:
        try:
            test_url = f"{url}?q={payload}"
            async with session.get(test_url, timeout=5, ssl=False) as response:
                content = await response.text()
                if payload in content:
                    results.append({
                        'payload': payload,
                        'vulnerable': True
                    })
        except Exception:
            pass
    
    return results

async def test_csrf(url, session):
    """Podstawowy test CSRF"""
    try:
        async with session.get(url, timeout=10, ssl=False) as response:
            content = await response.text()
            soup = BeautifulSoup(content, 'html.parser')
            forms = soup.find_all('form')
            
            csrf_tokens = []
            for form in forms:
                csrf_input = form.find('input', {'name': lambda x: x and 'csrf' in x.lower()})
                if csrf_input:
                    csrf_tokens.append(csrf_input.get('name'))
            
            return {
                'forms_found': len(forms),
                'csrf_protected_forms': len(csrf_tokens),
                'csrf_tokens': csrf_tokens
            }
    except Exception as e:
        return {'error': str(e)}

async def test_sql(url, session):
    """Podstawowy test SQL Injection"""
    sql_payloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "admin' --"
    ]
    
    results = []
    for payload in sql_payloads:
        try:
            test_url = f"{url}?id={payload}"
            async with session.get(test_url, timeout=5, ssl=False) as response:
                content = await response.text()
                
                sql_errors = ['sql syntax', 'mysql', 'postgresql', 'syntax error']
                found_errors = [err for err in sql_errors if err in content.lower()]
                
                if found_errors:
                    results.append({
                        'payload': payload,
                        'potential_vulnerability': True,
                        'errors_found': found_errors
                    })
        except Exception:
            pass
    
    return results

async def get_content(url, session):
    """Pobiera zawartość strony"""
    try:
        async with session.get(url, timeout=10, ssl=False) as response:
            return await response.text()
    except Exception as e:
        return str(e)

async def get_user_info(email):
    """Sprawdza obecność emaila na różnych platformach"""
    user_info = {}
    user_info['email'] = email
    user_info['note'] = 'Użyj: holehe ' + email
    return user_info

def run_sqlmap(url):
    """Uruchamia SQLMap"""
    try:
        command = ["sqlmap", "-u", url, "--batch", "--smart"]
        process = subprocess.run(command, capture_output=True, text=True, timeout=30)
        return process.stdout if process.returncode == 0 else process.stderr
    except FileNotFoundError:
        return "SQLMap nie jest zainstalowany"
    except Exception as e:
        return f"Błąd: {str(e)}"

async def check_https_security(url):
    """Sprawdza bezpieczeństwo HTTPS"""
    import ssl
    import urllib.parse
    
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname
    
    if not hostname:
        return {"error": "Invalid URL"}
    
    results = {
        'hostname': hostname,
        'port': parsed.port or 443
    }
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, results['port']), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                results['ssl_version'] = ssock.version()
                results['cipher'] = ssock.cipher()[0] if ssock.cipher() else 'Unknown'
                results['certificate'] = {
                    'subject': dict(x[0] for x in cert['subject']),
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'notBefore': cert['notBefore'],
                    'notAfter': cert['notAfter']
                }
    except Exception as e:
        results['error'] = str(e)
    
    return results

def create_chrome_driver():
    """Tworzy instancję Chrome WebDriver"""
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument(f"user-agent={UserAgent().random}")
    
    try:
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=options)
        return driver
    except Exception as e:
        print(f"Błąd WebDriver: {e}")
        return None

async def main():
    """Główna funkcja programu"""
    print("\n" + "="*50)
    print("     HTTPS SECURITY CHECKER v2.0")
    print("="*50 + "\n")
    
    user_agent = UserAgent().random
    
    async with aiohttp.ClientSession(
        headers={"User-Agent": user_agent},
        timeout=aiohttp.ClientTimeout(total=30)
    ) as session:
        
        # Pobierz dane od użytkownika lub użyj domyślnych
        domain = input("Podaj domenę (domyślnie: example.com): ").strip() or "example.com"
        url = f"https://{domain}"
        
        print(f"\n[1/6] Rozwiązywanie domeny {domain}...")
        ip_address = get_ip_from_domain(domain)
        if ip_address:
            print(f"   ✓ IP: {ip_address}")
            
            print(f"\n[2/6] Skanowanie portów (80, 443, 8080, 8443)...")
            common_ports = [80, 443, 8080, 8443]
            open_ports = []
            for port in common_ports:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                if s.connect_ex((ip_address, port)) == 0:
                    open_ports.append(port)
                s.close()
            print(f"   ✓ Otwarte porty: {open_ports if open_ports else 'Brak'}")
        else:
            print(f"   ✗ Nie można rozwiązać domeny")
        
        print(f"\n[3/6] Testowanie strony {url}...")
        website_info = await test_website(url, session)
        if 'error' not in website_info:
            print(f"   ✓ Status: {website_info.get('status', 'N/A')}")
            print(f"   ✓ Rozmiar: {website_info.get('content_length', 0)} bajtów")
            print(f"   Nagłówki bezpieczeństwa:")
            for header, value in website_info.get('security_headers', {}).items():
                status = "✓" if value != "Missing" else "✗"
                print(f"      {status} {header}: {value}")
        else:
            print(f"   ✗ Błąd: {website_info['error']}")
        
        print(f"\n[4/6] Sprawdzanie certyfikatu SSL/TLS...")
        https_info = await check_https_security(url)
        if 'error' not in https_info:
            print(f"   ✓ Protokół: {https_info.get('ssl_version', 'N/A')}")
            print(f"   ✓ Cipher: {https_info.get('cipher', 'N/A')}")
            cert = https_info.get('certificate', {})
            if cert:
                print(f"   ✓ Wystawca: {cert.get('issuer', {}).get('organizationName', 'N/A')}")
                print(f"   ✓ Ważny do: {cert.get('notAfter', 'N/A')}")
        else:
            print(f"   ✗ Błąd: {https_info['error']}")
        
        print(f"\n[5/6] Test podatności XSS...")
        xss_results = await test_xss(url, session)
        if xss_results:
            print(f"   ⚠ Znaleziono {len(xss_results)} potencjalnych podatności")
            for result in xss_results[:3]:
                print(f"      - {result.get('payload', '')[:50]}")
        else:
            print(f"   ✓ Nie znaleziono podatności XSS")
        
        print(f"\n[6/6] Test ochrony CSRF...")
        csrf_results = await test_csrf(url, session)
        if 'error' not in csrf_results:
            forms = csrf_results.get('forms_found', 0)
            protected = csrf_results.get('csrf_protected_forms', 0)
            print(f"   Formularze: {forms}")
            print(f"   Zabezpieczone: {protected}")
            if forms > 0 and protected == 0:
                print(f"   ⚠ Brak tokenów CSRF!")
            elif forms > 0:
                print(f"   ✓ Wykryto tokeny CSRF")
        else:
            print(f"   - Nie znaleziono formularzy")
        
        print("\n" + "="*50)
        print("Skanowanie zakończone!")
        print("="*50 + "\n")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n⚠ Przerwano przez użytkownika")
    except Exception as e:
        print(f"\n✗ Błąd krytyczny: {e}")
