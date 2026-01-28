🚀 SZYBKI START - HTTPS Security Checker v2.0
Naprawione problemy:
✅ localuseragent → fake-useragent ✅ executable_path → Service + webdriver-manager ✅ findelementbyid → findelement(By.ID, ...) ✅ Python 3.13 kompatybilność ✅ Async/await poprawki

Instalacja (3 kroki):
1️⃣ Aktywuj venv (jeśli już masz):
```bash source .venv/bin/activate ```

2️⃣ Zainstaluj nowe wymagania:
```bash pip install -r requirements.txt ```

3️⃣ Uruchom:
```bash python3 https-security-checker.py ```

Lub pełna reinstalacja:
```bash

Usuń stare venv
rm -rf .venv

Uruchom instalator
python3 install_script.py

Aktywuj i uruchom
source .venv/bin/activate python3 https-security-checker.py ```

Co zostało zmienione:
requirements.txt:
``` aiohttp>=3.9.0 beautifulsoup4>=4.12.0 holehe>=1.61 fake-useragent>=1.4.0 ← ZMIENIONE (było: localuseragent) scapy>=2.5.0 requests>=2.31.0 selenium>=4.16.0 webdriver-manager>=4.0.0 ← NOWE lxml>=5.0.0 ```

SecurityScanner.py:
✅ Nowe importy: from selenium.webdriver.chrome.service import Service
✅ Nowa funkcja: create_chrome_driver() z webdriver-manager
✅ Zaktualizowane API: find_element(By.ID, "id") zamiast find_element_by_id()
✅ Lepszy interfejs CLI z emoji i postępem
✅ Interaktywny input dla domeny
https-security-checker.py:
✅ Nowy wrapper z lepszą obsługą błędów
✅ Sprawdzanie środowiska
✅ Auto-instalacja wymagań
Test działania:
```bash (.venv) root@kali:/https-security-checker# python3 https-security-checker.py

HTTPS SECURITY CHECKER v2.0
Podaj domenę (domyślnie: example.com): example.com

[1/6] Rozwiązywanie domeny example.com... ✓ IP: 93.184.215.14

[2/6] Skanowanie portów (80, 443, 8080, 8443)... ✓ Otwarte porty: [80, 443]

[3/6] Testowanie strony https://example.com... ✓ Status: 200 ✓ Rozmiar: 1256 bajtów Nagłówki bezpieczeństwa: ✗ X-Frame-Options: Missing ✗ X-Content-Type-Options: Missing ✓ Strict-Transport-Security: max-age=... ...

[4/6] Sprawdzanie certyfikatu SSL/TLS... ✓ Protokół: TLSv1.3 ✓ Cipher: TLSAES256GCMSHA384 ...

[5/6] Test podatności XSS... ✓ Nie znaleziono podatności XSS

[6/6] Test ochrony CSRF... - Nie znaleziono formularzy

Skanowanie zakończone!
```

Troubleshooting:
Problem: ModuleNotFoundError: No module named 'fake_useragent'
Rozwiązanie: ```bash pip install fake-useragent ```

Problem: WebDriver.__init__() got an unexpected keyword argument 'executable_path'
Rozwiązanie: Już naprawione w nowej wersji! Używamy teraz: ```python from webdriver_manager.chrome import ChromeDriverManager service = Service(ChromeDriverManager().install()) driver = webdriver.Chrome(service=service, options=options) ```

Problem: AttributeError: 'WebDriver' object has no attribute 'find_element_by_id'
Rozwiązanie: Już naprawione! Używamy teraz: ```python element = driver.findelement(By.ID, "elementid") ```

Dla Kali Nethunter:
```bash

Jeśli nie masz Chrome/Chromium:
apt install chromium chromium-driver

Jeśli potrzebujesz SQLMap:
apt install sqlmap

Jeśli masz problemy z uprawnieniami:
sudo python3 https-security-checker.py ```

Powodzenia! 🛡️