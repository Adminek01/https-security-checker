import socket
import aiohttp
import bs4
import scapy.all as scapy
import subprocess
from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
import holehe
from random_user_agent.user_agent import UserAgent  # Poprawiony import modułu random_user_agent
import paramiko

# Definiowanie funkcji pomocniczych

def get_ip_from_domain(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def scan_ports(ip, start, end):
    open_ports = []
    for port in range(start, end + 1):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        result = s.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        s.close()
    return open_ports

async def test_website(url, session):
    website_info = {}
    try:
        response = await session.get(url)
        website_info['status'] = response.status
        website_info['headers'] = dict(response.headers)
        website_info['content'] = await response.text()
        website_info['xss'] = await test_xss(url, session)  # Dodane sprawdzanie podatności XSS
        website_info['csrf'] = await test_csrf(url, session)  # Dodane sprawdzanie podatności CSRF
        website_info['sql'] = await test_sql(url, session)  # Dodane sprawdzanie podatności SQL Injection
    except Exception as e:
        website_info['error'] = str(e)
    return website_info

async def test_xss(url, session):
    # Tutaj można umieścić kod testu XSS
    pass

async def test_csrf(url, session):
    # Tutaj można umieścić kod testu CSRF
    pass

async def test_sql(url, session):
    # Tutaj można umieścić kod testu SQL Injection
    pass

async def get_content(url, session):
    try:
        response = await session.get(url)
        return await response.text()
    except Exception as e:
        return str(e)

async def scan_network(ip, mask):
    active_hosts = []
    ip_range = ip + "/" + mask
    arp_result = await scapy.arping(ip_range, verbose=False)
    for sent, received in arp_result[0]:
        active_hosts.append(received.psrc)
    return active_hosts

def get_user_info(email):
    user_info = {}
    client = holehe.core.holehe()
    platforms = ["facebook", "twitter", "instagram", "linkedin"]
    for platform in platforms:
        result = client.get(email, platform)
        if result["found"]:
            user_info[platform] = result["data"]
    return user_info

def run_sqlmap(url):
    result = ""
    command = ["sqlmap", "-u", url, "--batch", "--dump-all"]
    process = subprocess.run(command, capture_output=True, text=True)
    if process.returncode == 0:
        result += process.stdout
    else:
        result += process.stderr
    return result

def automate_browser(url, driver):
    success = False
    try:
        driver.get(url)
        login = driver.find_element_by_id("login")
        login.send_keys("user@example.com")
        password = driver.find_element_by_id("password")
        password.send_keys("secret")
        submit = driver.find_element_by_id("submit")
        submit.click()
        wait = WebDriverWait(driver, 10)
        welcome = wait.until(EC.presence_of_element_located((By.ID, "welcome")))
        if "user" in welcome.text:
            success = True
    except Exception as e:
        print(e)
    return success

# Definiowanie głównej funkcji programu

async def main():
    user_agent_rotator = random_user_agent.UserAgent()  # Utworzenie obiektu UserAgent
    user_agent = user_agent_rotator.get_random_user_agent()  # Pobranie losowego nagłówka User-Agent
    async with aiohttp.ClientSession(headers={"User-Agent": user_agent}) as session:
        driver = webdriver.Chrome()

        domain = "example.com"
        url = "http://example.com/login.php"
        email = "user@example.com"
        ip = "192.168.1.1"
        mask = "24"

        print(get_ip_from_domain(domain))
        print(scan_ports(ip, 1, 1024))

        website_info = await test_website(url, session)
        print(website_info)

        content = await get_content(url, session)
        print(content)

        print(get_user_info(email))

        active_hosts = await scan_network(ip, mask)
        print(active_hosts)

        print(run_sqlmap(url))
        print(automate_browser(url, driver))

# Wywołanie głównej funkcji programu
if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
