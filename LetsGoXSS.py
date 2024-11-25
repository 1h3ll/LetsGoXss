from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import UnexpectedAlertPresentException, NoAlertPresentException, TimeoutException, WebDriverException
from colorama import init, Fore, Style
import os
import re
import argparse
import concurrent.futures
from threading import Lock
import time
import requests

# Global lock for synchronized printing
print_lock = Lock()

def safe_print(message):
    with print_lock:
        print(message)
        time.sleep(0.5)  # Add a 1-second delay for smoother, spaced-out output


# Initialize colorama
init(autoreset=True)

def setup_browser():
    chrome_options = Options()
    chrome_options.add_argument("--headless")  # Optional: Run in headless mode
    service = Service('./chromedriver')  # Update this path if necessary
    driver = webdriver.Chrome(service=service, options=chrome_options)
    return driver

def load_urls(url_argument):
    urls = []
    if os.path.isfile(url_argument):
        with open(url_argument, 'r') as file:
            urls = [line.strip() for line in file.readlines() if line.strip()]
    else:
        urls = [url_argument]
    return urls

def load_payloads(payload_file):
    with open(payload_file, 'r') as file:
        payloads = [line.strip() for line in file.readlines() if line.strip()]
    return payloads

def inject_payload(url, payload, inject_into_paths=False):
    injected_urls = []

    # Ensure payload is not injected into the protocol part (http:// or https://)
    if url.startswith("http://"):
        base_url = url[len("http://"):]
        protocol = "http://"
    elif url.startswith("https://"):
        base_url = url[len("https://"):]
        protocol = "https://"
    else:
        base_url = url
        protocol = ""

    # Handle cases where PAYLOAD is in the URL
    if 'PAYLOAD' in base_url:
        # Replace only the 'PAYLOAD' part with the actual payload
        injected_urls.append(protocol + base_url.replace("PAYLOAD", payload))
        return injected_urls  # Only inject into the 'PAYLOAD' placeholder and return

    # Continue with normal injection logic if '--path' is provided
    domain, *path_segments = base_url.split('/')
    if not domain:
        return injected_urls

    # Inject into each path segment if --path is specified
    if inject_into_paths:
        for i in range(1, len(path_segments) + 1):
            new_segments = path_segments[:i] + [payload] + path_segments[i:]
            injected_urls.append(protocol + domain + '/' + '/'.join(new_segments))

        # Inject into file extensions if --path is specified
        for i in range(len(path_segments)):
            if '.' in path_segments[i]:
                parts = path_segments[i].rsplit('.', 1)
                parts[0] += payload
                new_segment = '.'.join(parts)
                new_segments = path_segments[:i] + [new_segment] + path_segments[i + 1:]
                injected_urls.append(protocol + domain + '/' + '/'.join(new_segments))

    # Handle query parameters if present
    if '?' in base_url:
        base_path, query_params = base_url.split('?', 1)
        parameters = re.split(r'(?=&)|(?=&[^=&]+)', query_params)
        for param in parameters:
            if '=' in param:
                key, value = param.split('=', 1)
                if '&' in value:
                    # Multiple parameters, only replace the first one
                    new_param = f"{key}={payload}"
                    remaining_params = query_params.replace(param, new_param, 1)
                    injected_urls.append(protocol + f"{base_path}?{remaining_params}")
                else:
                    # Single parameter, replace the entire value
                    new_param = f"{key}={payload}"
                    remaining_params = query_params.replace(param, new_param)
                    injected_urls.append(protocol + f"{base_path}?{remaining_params}")
            else:
                # No valid parameter, add URL as is
                continue

    # Add the payload as a fragment identifier if --path is specified
    if inject_into_paths:
        injected_urls.append(f"{protocol}{base_url}#{payload}")

    return injected_urls

def test_payloads(urls, payloads, inject_into_paths=False):
    url_payload = []
    for url in urls:
        for payload in payloads:
            payload = payload.strip()
            injected_payload = inject_payload(url, payload, inject_into_paths)
            if isinstance(injected_payload, list):
                url_payload.extend(injected_payload)
            else:
                url_payload.append(injected_payload)
    return url_payload
    
def attack(test_url):
    driver = setup_browser()

    # Default values for status code and content length
    status_code = "N/A"
    content_length = "N/A"

    # Fetch status code and content length
    try:
        response = requests.get(test_url, timeout=10)
        status_code = response.status_code
        content_length = response.headers.get('Content-Length') or len(response.content)
    except requests.exceptions.RequestException as e:
        safe_print(Fore.RED + f"Failed to fetch URL details: {test_url}. Error: {str(e)}")
        return

    # Selenium handling for alerts
    try:
        driver.get(test_url)
        WebDriverWait(driver, 3).until(EC.alert_is_present())
        alert = driver.switch_to.alert
        alert.accept()
        safe_print(
            Fore.GREEN + f"Alert Found:" + Fore.YELLOW + f" {test_url}" +
            Fore.WHITE + f" [Status Code:" + Fore.CYAN + f" {status_code}" +
            Fore.WHITE + f"] [Content Length:" + Fore.CYAN + f" {content_length}" + Fore.WHITE + f"]"
        )
    except (TimeoutException, NoAlertPresentException):
        safe_print(
            Fore.RED + f"No alert:" + Fore.BLUE + f" {test_url}" +
            Fore.WHITE + f" [Status Code:" + Fore.CYAN + f" {status_code}" +
            Fore.WHITE + f"] [Content Length:" + Fore.CYAN + f" {content_length}" + Fore.WHITE + f"]"
        )
    except WebDriverException as e:
        if "ERR_NAME_NOT_RESOLVED" in str(e):
            safe_print(Fore.RED + f"DNS resolution failed for: {test_url}")
        else:
            safe_print(Fore.RED + f"WebDriverException: {str(e)}")
    except UnexpectedAlertPresentException:
        safe_print(Fore.RED + "Unexpected alert during execution.")
    except Exception as e:
        safe_print(Fore.RED + f"An error occurred: {str(e)}")
    finally:
        driver.quit()


def main():
    parser = argparse.ArgumentParser(description='Test XSS payloads.')
    parser.add_argument('--url', required=True, help='Single URL or path to a file containing URLs')
    parser.add_argument('--payload', required=True, help='Path to the payload file')
    parser.add_argument('--path', action='store_true', help='Inject into paths, fragments, and file extensions')
    parser.add_argument('--thread', type=int, default=10, help='Number of threads to use (default is 10)')
    args = parser.parse_args()

    urls = load_urls(args.url)
    payloads = load_payloads(args.payload)

    # Count URLs with parameters
    url_count = len(urls)
    payload_count = len(payloads)

    # Display the count before starting
    print(f"{Fore.MAGENTA}Number of URLs: {url_count}")
    print(f"{Fore.MAGENTA}Number of payloads: {payload_count}")
    print("Please give me atleast 30 sec....")

    # Run payload testing
    injected_payloads = test_payloads(urls, payloads, inject_into_paths=args.path)

    # Use thread argument or default to 10
    thread_count = args.thread
    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
        executor.map(attack, injected_payloads)

if __name__ == "__main__":
    main()
