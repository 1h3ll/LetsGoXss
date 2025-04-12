from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import (UnexpectedAlertPresentException,
                                      NoAlertPresentException,
                                      TimeoutException,
                                      WebDriverException)
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode
import os
import argparse
import concurrent.futures
from threading import Lock
import time
import requests
from colorama import init, Fore, Style
from rich.console import Console
from rich.table import Table

# Initialize console and colorama
console = Console()
init(autoreset=True)

# Global lock for thread-safe printing
print_lock = Lock()

def safe_print(message, alert=False):
    """Thread-safe printing with colored output"""
    with print_lock:
        if alert:
            console.print(f"[bold green]✓ {message}[/bold green]")
        else:
            console.print(f"[bold red]✗ {message}[/bold red]")

def print_banner():
    banner = r"""
██╗  ██╗███████╗███████╗
╚██╗██╔╝██╔════╝██╔════╝
 ╚███╔╝ ███████╗███████╗
 ██╔██╗ ╚════██║╚════██║
██╔╝ ██╗███████║███████║
╚═╝  ╚═╝╚══════╝╚══════╝
    """
    console.print(f"[bold cyan]{banner}[/bold cyan]")
    console.print("[bold yellow]XSS Hunter Pro - Advanced Web Vulnerability Scanner[/bold yellow]\n")
    console.print("[bold]Features:[/bold]")
    console.print("- [cyan]PAYLOAD[/cyan] placeholder targeting")
    console.print("- Multi-vector injection (params, paths, fragments)")
    console.print("- Real browser validation with Selenium")
    console.print("- Telegram alert integration\n")

def setup_browser():
    """Configure headless Chrome browser"""
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    service = Service('./chromedriver')
    driver = webdriver.Chrome(service=service, options=chrome_options)
    return driver

def load_urls(url_argument):
    """Load URLs from file or single URL"""
    urls = []
    if os.path.isfile(url_argument):
        with open(url_argument, 'r') as file:
            urls = [line.strip() for line in file if line.strip()]
    else:
        urls = [url_argument]
    return urls

def load_payloads(payload_file):
    """Load XSS payloads from file"""
    with open(payload_file, 'r') as file:
        return [line.strip() for line in file if line.strip()]

def inject_payload(url, payload, inject_into_paths=False):
    """
    Generate test URLs with payload injection
    Priority: PAYLOAD placeholder > parameter injection > path injection
    """
    # Check for PAYLOAD placeholder first
    if 'PAYLOAD' in url:
        return [url.replace('PAYLOAD', payload)]

    parsed = urlparse(url)
    query_params = parse_qs(parsed.query, keep_blank_values=True)
    injected_urls = []

    # Standard parameter injection
    for param in query_params:
        modified_params = query_params.copy()
        modified_params[param] = [payload]
        new_query = urlencode(modified_params, doseq=True)
        injected_urls.append(urlunparse(parsed._replace(query=new_query)))

    # Path/fragment injection (only with --path flag)
    if inject_into_paths:
        # Path segment injection
        path_segments = parsed.path.split('/')
        for i in range(1, len(path_segments)):
            new_path = '/'.join(path_segments[:i] + [payload] + path_segments[i:])
            injected_urls.append(urlunparse(parsed._replace(path=new_path)))

        # File extension injection
        if '.' in path_segments[-1]:
            filename, ext = path_segments[-1].rsplit('.', 1)
            new_filename = f"{filename}{payload}.{ext}"
            new_path = '/'.join(path_segments[:-1] + [new_filename])
            injected_urls.append(urlunparse(parsed._replace(path=new_path)))

        # Fragment injection
        injected_urls.append(urlunparse(parsed._replace(fragment=payload)))

    return injected_urls

def attack(test_url):
    """Test a single URL for XSS vulnerabilities"""
    driver = None
    try:
        # Get initial response details
        start_time = time.time()
        try:
            response = requests.get(test_url, timeout=5)
            status_code = response.status_code
            content_length = len(response.content)
        except requests.exceptions.RequestException:
            status_code = "N/A"
            content_length = "N/A"

        # Test with Selenium
        driver = setup_browser()
        driver.get(test_url)
        
        try:
            WebDriverWait(driver, 5).until(EC.alert_is_present())
            alert = driver.switch_to.alert
            alert_text = alert.text
            alert.accept()

            # Enhanced URL encoding for Telegram
            encoded_url = (
                test_url
                .replace('&', '%26')  # Encode ampersands first
                .replace(' ', '+')    # Then spaces
                .replace('"', '%22')  # Double quotes
                .replace("'", '%27')  # Single quotes
                .replace('>', '%3E')  # Greater than
                .replace('<', '%3C')  # Less than
            )
            
            # Telegram notification
            try:
                bot_token = 'your_telegram_BOT_ID'
                chat_id = 'your_CHAT_ID'
                telegram_url = (
                    f"https://api.telegram.org/bot{bot_token}/sendMessage?"
                    f"chat_id={chat_id}&"
                    f"text=XSS+Found:+{encoded_url}"
                )
                requests.get(telegram_url, timeout=3)
            except Exception as e:
                safe_print(f"Telegram notification failed: {str(e)}")

            # Print vulnerable result
            safe_print(
                f"Vulnerable: {test_url}\n"
                f"  ├─ Status: {status_code}\n"
                f"  ├─ Length: {content_length}\n"
                f"  ├─ Time: {time.time()-start_time:.2f}s\n"
                f"  └─ Alert: {alert_text}",
                alert=True
            )
        except (TimeoutException, NoAlertPresentException):
            safe_print(
                f"Not Vulnerable: {test_url}\n"
                f"  ├─ Status: {status_code}\n"
                f"  ├─ Length: {content_length}\n"
                f"  └─ Time: {time.time()-start_time:.2f}s"
            )
            
    except Exception as e:
        safe_print(f"Error testing {test_url}: {str(e)}")
    finally:
        if driver:
            driver.quit()

def main():
    print_banner()
    
    # Parse arguments
    parser = argparse.ArgumentParser(description='Advanced XSS Scanner')
    parser.add_argument('--url', required=True, help='URL or file containing URLs (can contain PAYLOAD placeholder)')
    parser.add_argument('--payload', required=True, help='File containing XSS payloads')
    parser.add_argument('--path', action='store_true', help='Enable path/fragment injection when no PAYLOAD placeholder exists')
    parser.add_argument('--thread', type=int, default=10, help='Number of threads (default: 10)')
    args = parser.parse_args()

    # Load targets and payloads
    urls = load_urls(args.url)
    payloads = load_payloads(args.payload)
    
    # Generate test cases
    test_cases = []
    for url in urls:
        for payload in payloads:
            test_cases.extend(inject_payload(url, payload, args.path))

    # Print summary table
    console.print("[bold]Scan Configuration Summary[/bold]")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="cyan")
    table.add_column("Count", justify="right")
    table.add_row("URLs to Test", str(len(urls)))
    table.add_row("Payloads Available", str(len(payloads)))
    table.add_row("Test Cases Generated", str(len(test_cases)))
    table.add_row("Threads", str(args.thread))
    table.add_row("Path Injection", "ENABLED" if args.path else "DISABLED")
    console.print(table)
    console.print(f"[bold green]Starting scan with {len(test_cases)} test cases...[/bold green]\n")

    # Execute tests
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.thread) as executor:
        executor.map(attack, test_cases)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[red]Scan interrupted by user![/red]")
    except Exception as e:
        console.print(f"[red]Fatal error: {str(e)}[/red]")
