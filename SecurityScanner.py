import socket
import aiohttp
import asyncio
import threading
import paramiko
import re
import logging
import argparse
import sys

# Stałe
TIMEOUT = 30  # Zwiększenie timeoutu do 30 sekund

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
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=TIMEOUT)) as session:
                url = f"http://{target}:{port}"
                async with session.get(url) as response:
                    if response.status == 200:
                        open_ports.append(port)
                        logging.info(f"Found open port: {port}")
        except aiohttp.ClientError as e:
            logging.error(f"An error occurred while scanning port {port}: {e}")
        except asyncio.TimeoutError as e:
            logging.warning(f"Timeout occurred while scanning port {port}: {e}")

    return open_ports

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

    # Zmniejszenie zakresu portów do skanowania
    start_port = 1
    end_port = 1024

    # Wywołanie funkcji asynchronicznej do skanowania portów
    open_ports = asyncio.run(scan_ports(target, start_port, end_port))
    print(f"Open ports on {target}: {open_ports}")
```

Po wprowadzeniu zmian i uruchomieniu tego kodu, powinien on obsłużyć timeouty oraz wyjątki podczas skanowania portów. W razie dodatkowych pytań lub problemów, daj znać, chętnie pomogę!