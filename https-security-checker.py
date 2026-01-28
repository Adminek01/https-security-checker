#!/usr/bin/env python3
"""
HTTPS Security Checker - Narzędzie do testowania bezpieczeństwa stron WWW
Wersja 2.0 - Zaktualizowana dla Python 3.13 i Selenium 4.x
"""

import os
import sys
import subprocess
import asyncio
from SecurityScanner import main

def install_requirements():
    """Instaluje wymagane pakiety z requirements.txt"""
    try:
        print("Sprawdzanie wymaganych pakietów...")
        with open('requirements.txt', 'r') as file:
            requirements = file.read().splitlines()
        
        for requirement in requirements:
            if requirement.strip() and not requirement.startswith('#'):
                print(f"Instalowanie: {requirement}")
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", requirement],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
        
        print("✓ Wszystkie pakiety zainstalowane\n")
        return True
        
    except FileNotFoundError:
        print("✗ Nie znaleziono pliku requirements.txt")
        return False
    except Exception as e:
        print(f"✗ Błąd podczas instalacji pakietów: {e}")
        return False

def check_environment():
    """Sprawdza środowisko uruchomieniowe"""
    print("Sprawdzanie środowiska...")
    
    # Sprawdź wersję Pythona
    if sys.version_info < (3, 8):
        print("✗ Wymagany Python 3.8 lub nowszy")
        return False
    print(f"✓ Python {sys.version_info.major}.{sys.version_info.minor}")
    
    # Sprawdź czy jesteśmy w venv
    in_venv = hasattr(sys, 'real_prefix') or (
        hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix
    )
    if in_venv:
        print(f"✓ Środowisko wirtualne: {sys.prefix}")
    else:
        print("⚠ Nie wykryto środowiska wirtualnego")
    
    return True

def main_wrapper():
    """Główna funkcja wrapper"""
    print("\n" + "="*60)
    print("  HTTPS SECURITY CHECKER - INSTALACJA I URUCHOMIENIE")
    print("="*60 + "\n")
    
    # Sprawdź środowisko
    if not check_environment():
        sys.exit(1)
    
    # Zainstaluj wymagania
    if not install_requirements():
        print("\n⚠ Kontynuowanie mimo błędów instalacji...")
    
    # Uruchom główny program
    try:
        print("Uruchamianie skanera bezpieczeństwa...\n")
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n⚠ Przerwano przez użytkownika")
        sys.exit(0)
    except Exception as e:
        print(f"\n✗ Błąd: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main_wrapper()
