import socket
import aiohttp
import asyncio
import threading
import paramiko
import re
from bs4 import BeautifulSoup
from holehe.core import *
from holehe.localuseragent import *
from scapy.all import *
import argparse
import logging
import random
import os
import sys
import subprocess

# Stałe
TIMEOUT = 10  # Zwiększenie timeoutu do 10 sekund

# Lista serwerów DNS (możesz dowolnie zmieniać lub dodawać inne)
DNS_SERVERS = ['1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4']

# Inicjalizacja loggera
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def validate_ip_address(ip):
    """
    Funkcja do walidacji adresu IP przy użyciu modułu re.
    """
    pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return re.match(pattern, ip) is not None

async def scan_ports(target, start_port, end_port):
    """
    Funkcja asynchronicznie skanująca porty na podanym adresie IP w danym zakresie.
    """
    if not validate_ip_address(target):
        try:
            target = socket.gethostbyname(target)  # Konwersja adresu URL na adres IP
        except socket.gaierror:
            logging.error("Invalid IP address or domain name.")
            return []

    open_ports = []
    for port in range(start_port, end_port + 1):
        try:
            async with aiohttp.ClientSession() as session:
                url = f"http://{target}:{port}"
                async with session.get(url, timeout=TIMEOUT) as response:
                    if response.status == 200:
                        open_ports.append(port)
                        logging.info(f"Found open port: {port}")
        except aiohttp.ClientError:
            pass
    return open_ports

async def test_http(target):
    """
    Funkcja asynchronicznie testująca stronę HTTP lub HTTPS na podanym celu.
    """
    if not validate_ip_address(target):
        try:
            target = socket.gethostbyname(target)  # Konwersja adresu URL na adres IP
        except socket.gaierror:
            logging.error("Invalid IP address or domain name.")
            return

    # Skanowanie portów 80 i 443
    ports = await scan_ports(target, 80, 443)
    logging.info(f"Scanned ports on {target}: {ports}")

    # Sprawdzanie, czy są otwarte porty HTTP lub HTTPS
    if 80 in ports or 443 in ports:
        # Wybieranie protokołu HTTP lub HTTPS
        protocol = "https" if 443 in ports else "http"
        # Tworzenie adresu URL
        url = f"{protocol}://{target}"
        # Wykonywanie żądania HTTP lub HTTPS
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=TIMEOUT) as response:
                    # Sprawdzanie statusu odpowiedzi
                    if response.status == 200:
                        # Odczytywanie treści odpowiedzi
                        content = await response.text()
                        # Wypisywanie treści odpowiedzi
                        print(f"HTTP response from {url}:")
                        print(content)
                    else:
                        logging.error(f"HTTP error from {url}: {response.status}")
        except aiohttp.ClientError as e:
            logging.error(f"HTTP request failed: {e}")
    else:
        logging.warning(f"No HTTP or HTTPS ports open on {target}")

async def sqlmap_scan(target_url):
    """
    Funkcja asynchroniczna do uruchamiania SQLMap w celu skanowania podatności SQL Injection na podanym adresie URL.
    """
    logging.info(f"Starting SQLMap scan on {target_url}...")
    subprocess.run(["sqlmap", "-u", target_url, "--batch"])

if __name__ == "__main__":
    # Parsowanie argumentów linii poleceń
    parser = argparse.ArgumentParser(description="Tool for ethical hacking purposes.")
    parser.add_argument("-t", "--target", help="Target IP address or URL")
    args = parser.parse_args()

    # Sprawdzanie, czy podano cel
    if args.target:
        target = args.target
    else:
        logging.error("No target specified.")
        sys.exit(1)

    # Ustawienie losowego adresu IP za pomocą proxy lub VPN
    # (do implementacji przez Ciebie)

    # Zmniejszenie zakresu portów do skanowania
    start_port = 1
    end_port = 1024

    # Wywołanie funkcji asynchronicznej do skanowania portów
    ports = asyncio.run(scan_ports(target, start_port, end_port))
    print(f"Open ports on {target}: {ports}")

    # Testowanie strony HTTP lub HTTPS
    asyncio.run(test_http(target))

    # Uruchomienie skanowania SQLMap
    target_url = f"http://{target}"  # Zakładamy, że strona jest dostępna przez HTTP
    asyncio.run(sqlmap_scan(target_url))
