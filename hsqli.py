#!/usr/bin/env python3
import re
import subprocess
import time
import argparse
from tqdm import tqdm
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor

# Argument parser for command-line options
parser = argparse.ArgumentParser(description="SQLi Header Scanner")
parser.add_argument("-l", "--urls", required=True, help="Path to the file containing URLs to test")
parser.add_argument("-p", "--payloads", required=True, help="Path to the file containing payloads")
parser.add_argument("-H", "--headers", required=True, help="Path to the file containing headers")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
parser.add_argument("-o", "--output", required=True, help="Path to the output file")
args = parser.parse_args()

# Load URLs from file
with open(args.urls) as f:
    urls = [line.strip() for line in f.readlines()]

# Load payloads from file
with open(args.payloads) as f:
    payloads = [line.strip() for line in f.readlines()]

# Load headers from file
with open(args.headers) as f:
    headers = [line.strip() for line in f.readlines()]

# Regex pattern to extract elapsed time from curl output
time_pattern = re.compile(r"elapsed (\d+:\d+\.\d+)")

# Initialize tracking variables
vulnerable_urls = []
vulnerable_payloads = {}

# Total requests for progress tracking
total_requests = len(urls) * len(payloads) * len(headers)
progress = 0
start_time = time.time()

# Function to send requests and check for SQLi vulnerability
def send_request(url, payload, header):
    global progress
    url = url.strip()
    payload = payload.strip()
    if args.verbose:
        print(f"Sending request to {url} with {header} payload '{payload}'...")

    # Send curl request with payload in the specified header
    start_time = time.monotonic()
    try:
        output = subprocess.check_output(
            ["time", "curl", "-s", "-H", f"{header}: {payload}", url], stderr=subprocess.STDOUT
        )
    except subprocess.CalledProcessError as e:
        if args.verbose:
            print(f"Error accessing {url}: {e.output.decode()}")
        return

    end_time = time.monotonic()

    # Extract elapsed time from curl output
    match = time_pattern.search(output.decode(errors="replace"))
    elapsed_time = match.group(1) if match else "not-vuln"

    # Check if the response time indicates a potential vulnerability (>= 10 seconds)
    if end_time - start_time >= 10:
        if url not in vulnerable_urls:
            vulnerable_urls.append(url)
            vulnerable_payloads[url] = []
        vulnerable_payloads[url].append(f"{header}: {payload}")

        message = f"\n{colored(f'TIME BASED SQL FOUND ON {header}', 'white')} {colored(url, 'red')} with header payload {colored(payload, 'red')}"
        print(message)
    else:
        if args.verbose:
            print(colored(f"{url}: safe with {header} payload {payload} (safe: {elapsed_time})", 'green'))

    # Update progress
    progress += 1
    elapsed_seconds = time.time() - start_time
    remaining_seconds = (total_requests - progress) * (elapsed_seconds / progress)
    remaining_hours = int(remaining_seconds // 3600)
    remaining_minutes = int((remaining_seconds % 3600) // 60)
    percent_complete = round(progress / total_requests * 100, 2)

    # Progress update
    if args.verbose:
        print(f"{colored('Progress:', 'blue')} {progress}/{total_requests} ({percent_complete}%) - {remaining_hours}h:{remaining_minutes:02d}m")

    # Delay for 0.5 seconds between requests
    time.sleep(0.5)

# Use ThreadPoolExecutor for multithreading with 10 workers
with ThreadPoolExecutor(max_workers=10) as executor:
    for url in urls:
        for payload in payloads:
            for header in headers:
                executor.submit(send_request, url, payload, header)

# Write the results to the output file
if vulnerable_urls:
    with open(args.output, "w") as f:
        for url in vulnerable_urls:
            f.write(f"{url}\n")
            if url in vulnerable_payloads:
                f.write(f"Payloads: {', '.join(vulnerable_payloads[url])}\n")
        print(f"Results saved to {args.output}")
else:
    print("No vulnerabilities found.")

