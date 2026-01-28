#!/usr/bin/env python3
"""
Skrypt instalacyjny dla HTTPS Security Checker
Obsługuje Kali Linux / Nethunter i inne dystrybucje
"""

import os
import sys
import subprocess
import platform

def run_command(command, description):
    """Wykonuje komendę systemową z opisem"""
    print(f"\n[*] {description}...")
    try:
        result = subprocess.run(
            command,
            shell=True,
            check=True,
            capture_output=True,
            text=True
        )
        print(f"✓ {description} - OK")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ {description} - BŁĄD")
        if e.stderr:
            print(f"   Szczegóły: {e.stderr[:200]}")
        return False

def check_python_version():
    """Sprawdza wersję Pythona"""
    version = sys.version_info
    print(f"Python: {version.major}.{version.minor}.{version.micro}")
    
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print("✗ Wymagany Python 3.8 lub nowszy")
        return False
    
    print("✓ Wersja Pythona OK")
    return True

def install_system_dependencies():
    """Instaluje zależności systemowe"""
    print("\n=== INSTALACJA ZALEŻNOŚCI SYSTEMOWYCH ===")
    
    # Wykryj system
    is_kali = os.path.exists('/etc/apt/sources.list.d/kali.list')
    is_debian = os.path.exists('/etc/debian_version')
    
    if is_kali or is_debian:
        print("Wykryto system oparty na Debianie/Kali")
        
        # Aktualizuj listę pakietów
        run_command("apt-get update -qq", "Aktualizacja listy pakietów")
        
        # Instaluj podstawowe narzędzia
        packages = [
            "python3-pip",
            "python3-venv",
            "python3-dev",
            "build-essential",
            "libssl-dev",
            "libffi-dev",
            "chromium",
            "chromium-driver"
        ]
        
        for package in packages:
            run_command(
                f"apt-get install -y -qq {package}",
                f"Instalacja {package}"
            )
    else:
        print("⚠ Nierozpoznany system - pomijam instalację systemową")
        print("  Upewnij się, że masz zainstalowane:")
        print("  - Python 3.8+")
        print("  - pip")
        print("  - Chrome/Chromium")

def create_venv():
    """Tworzy środowisko wirtualne"""
    print("\n=== TWORZENIE ŚRODOWISKA WIRTUALNEGO ===")
    
    venv_path = ".venv"
    
    if os.path.exists(venv_path):
        print(f"⚠ Środowisko {venv_path} już istnieje")
        response = input("Czy chcesz je usunąć i utworzyć nowe? (t/n): ")
        if response.lower() == 't':
            run_command(f"rm -rf {venv_path}", f"Usuwanie {venv_path}")
        else:
            print("Używam istniejącego środowiska")
            return True
    
    return run_command(
        f"{sys.executable} -m venv {venv_path}",
        "Tworzenie środowiska wirtualnego"
    )

def install_python_packages():
    """Instaluje pakiety Pythona"""
    print("\n=== INSTALACJA PAKIETÓW PYTHON ===")
    
    # Znajdź pip w venv
    if os.path.exists(".venv/bin/pip"):
        pip_path = ".venv/bin/pip"
    elif os.path.exists(".venv/Scripts/pip.exe"):
        pip_path = ".venv/Scripts/pip.exe"
    else:
        print("✗ Nie znaleziono pip w środowisku wirtualnym")
        return False
    
    # Aktualizuj pip
    run_command(
        f"{pip_path} install --upgrade pip setuptools wheel",
        "Aktualizacja pip"
    )
    
    # Instaluj wymagania
    if os.path.exists("requirements.txt"):
        return run_command(
            f"{pip_path} install -r requirements.txt",
            "Instalacja pakietów z requirements.txt"
        )
    else:
        print("✗ Nie znaleziono requirements.txt")
        return False

def create_run_script():
    """Tworzy skrypt uruchamiający"""
    print("\n=== TWORZENIE SKRYPTU URUCHAMIAJĄCEGO ===")
    
    script_content = """#!/bin/bash
# Skrypt uruchamiający HTTPS Security Checker

# Aktywuj środowisko wirtualne
if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
else
    echo "✗ Nie znaleziono środowiska wirtualnego"
    echo "  Uruchom: python3 install_script.py"
    exit 1
fi

# Uruchom skaner
python3 https-security-checker.py "$@"
"""
    
    try:
        with open("run.sh", "w") as f:
            f.write(script_content)
        os.chmod("run.sh", 0o755)
        print("✓ Utworzono run.sh")
        return True
    except Exception as e:
        print(f"✗ Błąd tworzenia run.sh: {e}")
        return False

def print_usage():
    """Wyświetla instrukcje użycia"""
    print("\n" + "="*60)
    print("  INSTALACJA ZAKOŃCZONA")
    print("="*60)
    print("\nAby uruchomić skaner:")
    print("  1. Aktywuj środowisko wirtualne:")
    print("     source .venv/bin/activate")
    print("")
    print("  2. Uruchom skaner:")
    print("     python3 https-security-checker.py")
    print("")
    print("  LUB użyj skryptu:")
    print("     ./run.sh")
    print("")
    print("Dodatkowe narzędzia:")
    print("  - SQLMap: apt install sqlmap")
    print("  - Holehe: pip install holehe")
    print("="*60 + "\n")

def main():
    """Główna funkcja instalacyjna"""
    print("\n" + "="*60)
    print("  HTTPS SECURITY CHECKER - INSTALATOR")
    print("="*60 + "\n")
    
    # Sprawdź czy jesteśmy rootem (wymagane dla niektórych operacji)
    if os.geteuid() != 0:
        print("⚠ Nie uruchomiono jako root")
        print("  Niektóre funkcje mogą wymagać uprawnień sudo")
        print("")
    
    # Sprawdź Pythona
    if not check_python_version():
        sys.exit(1)
    
    # Instaluj zależności systemowe
    if os.geteuid() == 0:
        install_system_dependencies()
    else:
        print("\n⚠ Pomijam instalację systemową (wymagany root)")
    
    # Utwórz venv
    if not create_venv():
        print("✗ Nie udało się utworzyć środowiska wirtualnego")
        sys.exit(1)
    
    # Instaluj pakiety Pythona
    if not install_python_packages():
        print("✗ Nie udało się zainstalować pakietów")
        sys.exit(1)
    
    # Utwórz skrypt uruchamiający
    create_run_script()
    
    # Wyświetl instrukcje
    print_usage()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠ Instalacja przerwana przez użytkownika")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Błąd krytyczny: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
