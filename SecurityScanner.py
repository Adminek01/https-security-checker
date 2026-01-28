import socket
import aiohttp
from bs4 import BeautifulSoup
import asyncio
import subprocess
from fake_useragent import UserAgent
import ssl
import urllib.parse

# --- FUNKCJE POMOCNICZE ---

def get_ip_from_domain(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def check_security_headers(headers):
    security_headers = {
        'X-Frame-Options': headers.get('X-Frame-Options'),
        'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
        'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
        'Content-Security-Policy': headers.get('Content-Security-Policy'),
        'X-XSS-Protection': headers.get('X-XSS-Protection')
    }
    return {k: v if v else 'Missing' for k, v in security_headers.items()}

# --- MODUŁY TESTOWE ---

async def test_website(url, session):
    website_info = {}
    try:
        # Zwiększony timeout i obsługa przekierowań
        async with session.get(url, timeout=15, ssl=False, allow_redirects=True) as response:
            website_info['status'] = response.status
            website_info['headers'] = dict(response.headers)
            content = await response.text()
            website_info['content_length'] = len(content)
            website_info['security_headers'] = check_security_headers(response.headers)
    except aiohttp.ClientResponseError as e:
        website_info['error'] = f"Błąd odpowiedzi: {e.status}"
    except Exception as e:
        website_info['error'] = f"Błąd: {str(e)[:50]}..." 
    return website_info

async def test_xss(url, session):
    test_payloads = ["<script>alert(1)</script>", "'><img src=x onerror=alert(1)>"]
    results = []
    for payload in test_payloads:
        try:
            async with session.get(f"{url}?q={payload}", timeout=5, ssl=False) as response:
                if payload in await response.text():
                    results.append(payload)
        except: pass
    return results

async def test_csrf(url, session):
    try:
        async with session.get(url, timeout=10, ssl=False) as response:
            soup = BeautifulSoup(await response.text(), 'html.parser')
            forms = soup.find_all('form')
            # Szukamy tokenów w polach hidden
            protected = [f for f in forms if f.find('input', {'name': lambda x: x and 'csrf' in x.lower()})]
            return {'found': len(forms), 'protected': len(protected)}
    except: return {'found': 0, 'protected': 0}

async def check_https_security(url):
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or 443
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return {
                    'ver': ssock.version(),
                    'cipher': ssock.cipher()[0],
                    'issuer': dict(x[0] for x in cert['issuer']).get('organizationName', 'N/A'),
                    'expiry': cert['notAfter']
                }
    except Exception as e: return {'error': str(e)}

# --- GŁÓWNY PROGRAM ---

async def main():
    print(f"\n{'='*50}\n     HTTPS SECURITY CHECKER v2.1 (Tuned by Lena)\n{'='*50}")
    
    domain = input("Podaj domenę (np. twitter.com): ").strip() or "example.com"
    url = f"https://{domain}"
    ua = UserAgent().random

    # KLUCZOWA POPRAWKA: max_line_size i max_field_size dla Twittera/Cloudflare
    jar = aiohttp.CookieJar(unsafe=True)
    async with aiohttp.ClientSession(
        headers={"User-Agent": ua},
        cookie_jar=jar,
        max_line_size=32768, 
        max_field_size=32768
    ) as session:

        print(f"\n[1/6] Skanowanie: {domain}")
        ip = get_ip_from_domain(domain)
        if ip: print(f"   ✓ IP: {ip}")

        print(f"\n[2/6] Porty...")
        open_p = []
        for p in [80, 443, 8080, 8443]:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.3)
                if s.connect_ex((ip, p)) == 0: open_p.append(p)
        print(f"   ✓ Otwarte: {open_p}")

        print(f"\n[3/6] Nagłówki (Deep Scan)...")
        info = await test_website(url, session)
        if 'error' not in info:
            print(f"   ✓ Status: {info['status']}")
            for h, v in info['security_headers'].items():
                print(f"      {'✓' if v != 'Missing' else '✗'} {h}: {v}")
        else: print(f"   ✗ {info['error']}")

        print(f"\n[4/6] SSL/TLS...")
        ssl_i = await check_https_security(url)
        if 'error' not in ssl_i:
            print(f"   ✓ {ssl_i['ver']} | {ssl_i['cipher']}")
            print(f"   ✓ Wystawca: {ssl_i['issuer']}")
        else: print(f"   ✗ {ssl_i['error']}")

        print(f"\n[5/6] XSS & [6/6] CSRF...")
        xss = await test_xss(url, session)
        csrf = await test_csrf(url, session)
        print(f"   ✓ XSS: {'Podatny!' if xss else 'Bezpieczny'}")
        print(f"   ✓ CSRF: Formularze {csrf['found']}, Chronione {csrf['protected']}")

    print(f"\n{'='*50}\nSkanowanie zakończone! 📱💀💜😼\n{'='*50}")

if __name__ == "__main__":
    asyncio.run(main())
