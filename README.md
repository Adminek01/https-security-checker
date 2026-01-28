HTTPS Security Checker v2.0
Narzędzie do testowania bezpieczeństwa stron WWW - zaktualizowane dla Python 3.13 i Selenium 4.x
 
🚀 Funkcje
✅ Testowanie dostępności strony
🔒 Analiza certyfikatów SSL/TLS
🛡️ Sprawdzanie nagłówków bezpieczeństwa
🔍 Wykrywanie podatności XSS
🛡️ Test ochrony CSRF
🌐 Rozwiązywanie domen i skanowanie portów
📊 Szczegółowe raporty
📋 Wymagania
Python 3.8 lub nowszy (testowane na Python 3.13)
Kali Linux / Nethunter / Debian (lub inna dystrybucja z apt)
Chrome/Chromium (opcjonalne, dla zaawansowanych testów)
🔧 Instalacja
Metoda 1: Automatyczna instalacja
```bash

Jako root (zalecane dla pełnej instalacji)
sudo python3 install_script.py

Lub bez uprawnień root (tylko pakiety Python)
python3 install_script.py ```

Metoda 2: Ręczna instalacja
```bash

1. Utwórz środowisko wirtualne
python3 -m venv .venv

2. Aktywuj środowisko
source .venv/bin/activate

3. Zainstaluj wymagania
pip install -r requirements.txt ```

🎯 Użycie
Szybki start
```bash

Aktywuj środowisko wirtualne
source .venv/bin/activate

Uruchom skaner
python3 https-security-checker.py ```

Użycie skryptu uruchamiającego
```bash ./run.sh ```

Przykładowe skanowanie
Program poprosi o domenę do skanowania: ``` Podaj domenę (domyślnie: example.com): google.com ```

📊 Co jest sprawdzane?
Rozwiązywanie domeny - Konwersja nazwy domeny na adres IP
Skanowanie portów - Sprawdzanie otwartych portów (80, 443, 8080, 8443)
Status HTTP/HTTPS - Kod odpowiedzi serwera
Nagłówki bezpieczeństwa:
X-Frame-Options
X-Content-Type-Options
Strict-Transport-Security (HSTS)
Content-Security-Policy
X-XSS-Protection
Certyfikat SSL/TLS:
Protokół (TLS 1.2, 1.3)
Cipher suite
Wystawca
Ważność
Podatności XSS - Podstawowe testy Cross-Site Scripting
Ochrona CSRF - Wykrywanie tokenów CSRF w formularzach
🔍 Dodatkowe narzędzia
SQLMap (testy SQL Injection)
```bash apt install sqlmap ```

Holehe (wyszukiwanie emaili)
```bash pip install holehe holehe user@example.com ```

⚙️ Konfiguracja
Zmiana celów skanowania
Edytuj SecurityScanner.py i zmień domyślne wartości: ```python domain = "example.com" # Zmień na swoją domenę ```

Dostosowanie skanowania portów
Możesz zmodyfikować listę portów w funkcji main(): ```python common_ports = [80, 443, 8080, 8443, 3000, 5000] # Dodaj więcej portów ```

🛠️ Rozwiązywanie problemów
Błąd: "local_user_agent not found"
Ten pakiet nie istnieje. Projekt został zaktualizowany do używania fake-useragent.

Błąd: "executable_path deprecated"
Zaktualizowano do Selenium 4.x API z webdriver-manager.

Błąd: "find_element_by_id deprecated"
Zaktualizowano do nowego API: find_element(By.ID, "element_id").

Brak uprawnień do skanowania portów
Niektóre operacje mogą wymagać uprawnień root: ```bash sudo python3 https-security-checker.py ```

Błąd ChromeDriver
Jeśli masz problemy z ChromeDriver: ```bash

Zainstaluj Chromium
apt install chromium chromium-driver

Lub pozwól webdriver-manager pobrać go automatycznie
```

📝 Struktura projektu
``` https-security-checker/ ├── https-security-checker.py # Główny plik uruchomieniowy ├── SecurityScanner.py # Moduł z funkcjami skanowania ├── install_script.py # Skrypt instalacyjny ├── requirements.txt # Zależności Python ├── run.sh # Skrypt uruchamiający (tworzony przez instalator) ├── README.md # Ta dokumentacja └── LICENSE # Licencja ```

🔐 Bezpieczeństwo i etyka
WAŻNE: To narzędzie jest przeznaczone wyłącznie do testowania własnych systemów lub systemów, do których masz wyraźne pozwolenie na testowanie.

❌ NIE używaj tego narzędzia na stronach bez zgody właściciela
❌ NIE wykorzystuj znalezionych podatności do szkodzenia
✅ Używaj tylko do celów edukacyjnych i legalnych testów penetracyjnych
✅ Zawsze uzyskaj pisemną zgodę przed testowaniem
🐛 Znane ograniczenia
Testy XSS i SQL Injection są podstawowe i mogą nie wykryć wszystkich podatności
Skanowanie sieci może wymagać uprawnień root
Niektóre funkcje mogą być zablokowane przez firewall lub WAF
Wyniki powinny być zweryfikowane przez profesjonalne narzędzia
🔄 Co nowego w wersji 2.0?
✅ Kompatybilność z Python 3.13
✅ Zaktualizowane API Selenium 4.x
✅ Poprawiony fake-useragent (zastąpienie localuseragent)
✅ Lepsze zarządzanie ChromeDriver (webdriver-manager)
✅ Ulepszona obsługa błędów
✅ Nowy interfejs użytkownika z emoji i kolorami
✅ Lepsze raportowanie wyników
✅ Asynchroniczne operacje dla lepszej wydajności
📄 Licencja
Zobacz plik LICENSE

👨‍💻 Autor
Projekt zaktualizowany i zmodernizowany dla Kali Nethunter i Python 3.13

🤝 Współpraca
Pull requesty są mile widziane! Dla większych zmian, najpierw otwórz issue aby omówić co chciałbyś zmienić.

📞 Wsparcie
Jeśli napotkasz problemy: 1. Sprawdź sekcję "Rozwiązywanie problemów" 2. Upewnij się, że masz najnowsze wersje pakietów 3. Zgłoś issue z pełnym błędem i informacją o systemie

Pamiętaj: Używaj odpowiedzialnie i legalnie! 🛡️