#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
API Interaction in Python for Cybersecurity
This script demonstrates working with APIs, OAuth, and RESTful services
with cybersecurity-relevant examples and detailed explanations.
Perfect for beginners!
"""

# Import necessary modules
import requests                  # For making HTTP requests
import json                      # For JSON data handling
import time                      # For delays and timing
import hashlib                   # For cryptographic hashing
import base64                    # For encoding/decoding
from datetime import datetime    # For date/time operations

# ==========================================
# 1. RESTful API Basics
# ==========================================
print("=== RESTful API Basics ===\n")

def make_api_request(url, method='GET', params=None, data=None, headers=None):
    """
    Make HTTP request to API endpoint.
    
    Args:
        url: API endpoint URL
        method: HTTP method (GET, POST, PUT, DELETE, etc.)
        params: Query parameters to include in request
        data: Request body data (for POST/PUT)
        headers: Request headers
        
    Returns:
        Dictionary containing response data
    """
    # Default headers
    if headers is None:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json'
        }
        
    try:
        # Make the HTTP request
        if method == 'GET':
            response = requests.get(url, params=params, headers=headers)
        elif method == 'POST':
            response = requests.post(url, params=params, json=data, headers=headers)
        elif method == 'PUT':
            response = requests.put(url, params=params, json=data, headers=headers)
        elif method == 'DELETE':
            response = requests.delete(url, params=params, headers=headers)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")
            
        # Check if request was successful
        response.raise_for_status()
        
        # Try to parse JSON response
        try:
            return response.json()
        except ValueError:
            return {'content': response.text}
            
    except requests.exceptions.RequestException as e:
        print(f"Error making API request: {e}")
        return {'error': str(e), 'status_code': getattr(e.response, 'status_code', None)}

# Test API request to ipapi for IP geolocation
test_ip = "8.8.8.8"
print(f"Checking geolocation for IP {test_ip}...")
geo_data = make_api_request(f"https://ipapi.co/{test_ip}/json/")

if 'error' not in geo_data:
    print(f"\nLocation Data:")
    print(f"  IP Address: {geo_data.get('ip', 'N/A')}")
    print(f"  Country: {geo_data.get('country_name', 'N/A')}")
    print(f"  City: {geo_data.get('city', 'N/A')}")
    print(f"  ISP: {geo_data.get('org', 'N/A')}")
    print(f"  Timezone: {geo_data.get('timezone', 'N/A')}")
else:
    print(f"Error: {geo_data['error']}")

print()
print("=" * 50)
print()

# ==========================================
# 2. API Authentication
# ==========================================
print("=== API Authentication ===\n")

def api_authentication_demo():
    """Demonstrate different API authentication methods"""
    
    print("=== API Authentication Methods ===\n")
    
    # Basic Authentication
    print("1. Basic Authentication")
    auth_user = 'test_user'
    auth_pass = 'test_password'
    
    # Note: This is a test endpoint - it will fail with 404
    test_url = "https://httpbin.org/basic-auth/test/test"
    try:
        response = requests.get(test_url, auth=(auth_user, auth_pass))
        print(f"  Status Code: {response.status_code}")
        if response.status_code == 200:
            print(f"  Response: {response.json()}")
    except Exception as e:
        print(f"  Error: {e}")
        
    print()
    
    # API Key Authentication
    print("2. API Key Authentication")
    api_key = "your_api_key_here"
    # This is a test endpoint for CoinGecko API (no API key required for public data)
    coingecko_url = "https://api.coingecko.com/api/v3/simple/price"
    params = {
        'ids': 'bitcoin',
        'vs_currencies': 'usd'
    }
    
    try:
        response = requests.get(coingecko_url, params=params)
        print(f"  Status Code: {response.status_code}")
        if response.status_code == 200:
            print(f"  Bitcoin Price: ${response.json()['bitcoin']['usd']}")
    except Exception as e:
        print(f"  Error: {e}")
        
    print()
    
    # Bearer Token Authentication (JWT)
    print("3. Bearer Token Authentication (JWT)")
    fake_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    
    try:
        headers = {
            'Authorization': f'Bearer {fake_token}',
            'Content-Type': 'application/json'
        }
        
        # This is a test endpoint
        response = requests.get("https://httpbin.org/get", headers=headers)
        print(f"  Status Code: {response.status_code}")
    except Exception as e:
        print(f"  Error: {e}")

api_authentication_demo()

print()
print("=" * 50)
print()

# ==========================================
# 3. API Rate Limiting
# ==========================================
print("=== API Rate Limiting ===\n")

def rate_limited_api_call(url, max_retries=3, retry_delay=2):
    """
    Make API call with rate limiting and retry logic.
    
    Args:
        url: API endpoint to call
        max_retries: Maximum number of retry attempts
        retry_delay: Delay between retries in seconds
        
    Returns:
        Response from API or None on failure
    """
    for attempt in range(1, max_retries + 1):
        try:
            response = requests.get(url)
            
            if response.status_code == 200:
                return response.json()
                
            elif response.status_code == 429:
                print(f"Rate limit hit (attempt {attempt}/{max_retries}) - waiting {retry_delay} seconds")
                time.sleep(retry_delay)
                retry_delay *= 2  # Exponential backoff
                
            else:
                print(f"Error {response.status_code} (attempt {attempt}/{max_retries})")
                time.sleep(retry_delay)
                
        except Exception as e:
            print(f"Error: {e} (attempt {attempt}/{max_retries})")
            time.sleep(retry_delay)
            
    return None

# Test rate limited API call
print("Testing rate limited API call...")
for i in range(5):
    print(f"\nCall {i+1}:")
    result = rate_limited_api_call(f"https://httpbin.org/delay/1")
    if result:
        print("  Success!")

print()
print("=" * 50)
print()

# ==========================================
# 4. API Security Testing
# ==========================================
print("=== API Security Testing ===\n")

def check_api_security(url, endpoints):
    """
    Check basic security aspects of API endpoints.
    
    Args:
        url: Base API URL
        endpoints: List of endpoints to test
        
    Returns:
        Dictionary of security findings
    """
    findings = []
    
    for endpoint in endpoints:
        full_url = f"{url.rstrip('/')}/{endpoint.lstrip('/')}"
        
        print(f"\nChecking endpoint: {full_url}")
        
        # Check if endpoint returns sensitive headers
        try:
            response = requests.get(full_url)
            
            # Check for security headers
            security_headers = {
                'Strict-Transport-Security': 'HSTS not configured',
                'X-Frame-Options': 'Clickjacking protection not configured',
                'X-XSS-Protection': 'XSS protection not configured',
                'X-Content-Type-Options': 'MIME type sniffing not disabled',
                'Referrer-Policy': 'Referrer policy not configured'
            }
            
            for header, issue in security_headers.items():
                if header not in response.headers:
                    findings.append({
                        'url': full_url,
                        'endpoint': endpoint,
                        'issue': issue
                    })
                    print(f"  ⚠️  {issue}")
                    
            # Check if server header reveals sensitive information
            if 'Server' in response.headers:
                print(f"  Server header: {response.headers['Server']}")
                
            # Check if content type is JSON
            if 'Content-Type' in response.headers:
                print(f"  Content-Type: {response.headers['Content-Type']}")
                
        except Exception as e:
            findings.append({
                'url': full_url,
                'endpoint': endpoint,
                'issue': f"Error accessing endpoint: {e}"
            })
            print(f"  ❌ Error: {e}")
            
    return findings

# Test API security checking on httpbin
test_api_url = "https://httpbin.org"
test_endpoints = [
    "get", 
    "post", 
    "status/200", 
    "headers"
]

print("Checking API security...")
security_findings = check_api_security(test_api_url, test_endpoints)

if security_findings:
    print(f"\nTotal findings: {len(security_findings)}")
    
    # Count by severity
    severity_counts = {}
    for finding in security_findings:
        severity = 'medium'
        if 'Error' in finding['issue']:
            severity = 'critical'
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
    for severity, count in severity_counts.items():
        print(f"  {severity.capitalize()}: {count}")

print()
print("=" * 50)
print()

# ==========================================
# 5. OAuth 2.0 Flow (Simplified)
# ==========================================
print("=== OAuth 2.0 Flow ===\n")

def simulate_oauth_flow():
    """Simulate a simplified OAuth 2.0 authorization flow"""
    
    print("=== OAuth 2.0 Authorization Code Flow ===\n")
    
    # Step 1: Redirect user to authorization server
    print("Step 1: Redirect user to OAuth provider")
    auth_url = ("https://oauth.example.com/authorize"
               "?response_type=code"
               "&client_id=YOUR_CLIENT_ID"
               "&redirect_uri=https://your-app.com/callback"
               "&scope=read write"
               "&state=random_state_value")
    print(f"  Authorization URL: {auth_url}")
    
    print()
    
    # Step 2: User authenticates and grant permissions
    print("Step 2: User authenticates and grants permissions")
    print("  - User logs in")
    print("  - User reviews permissions")
    print("  - User clicks 'Authorize'")
    
    print()
    
    # Step 3: Receive authorization code
    print("Step 3: Receive authorization code")
    auth_code = "code_1234567890"
    print(f"  Authorization Code: {auth_code}")
    
    print()
    
    # Step 4: Exchange code for access token
    print("Step 4: Exchange code for access token")
    token_url = "https://oauth.example.com/token"
    token_data = {
        'grant_type': 'authorization_code',
        'code': auth_code,
        'redirect_uri': 'https://your-app.com/callback',
        'client_id': 'YOUR_CLIENT_ID',
        'client_secret': 'YOUR_CLIENT_SECRET'
    }
    
    try:
        # This is a simulated call - it will fail
        response = requests.post(token_url, data=token_data)
        print(f"  Status Code: {response.status_code}")
        # Token response would look like this:
        print(f"  Response:")
        print(f"  {{")
        print(f"    \"access_token\": \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...\",")
        print(f"    \"token_type\": \"Bearer\",")
        print(f"    \"expires_in\": 3600,")
        print(f"    \"refresh_token\": \"refresh_token_abc123...\",")
        print(f"    \"scope\": \"read write\"")
        print(f"  }}")
        
    except Exception as e:
        print(f"  Error: {e}")
        
    print()
    
    # Step 5: Use access token to access protected resources
    print("Step 5: Use access token to access protected resources")
    api_data = {
        'user_profile': 'https://api.example.com/me',
        'files': 'https://api.example.com/files',
        'messages': 'https://api.example.com/messages'
    }
    
    for resource, endpoint in api_data.items():
        print(f"  Accessing {resource}:")
        try:
            response = requests.get(endpoint, headers={
                'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
            })
            print(f"  Success! Status: {response.status_code}")
        except Exception as e:
            print(f"  Error: {e}")

simulate_oauth_flow()

print()
print("=" * 50)
print()

# ==========================================
# 6. API Data Analysis
# ==========================================
print("=== API Data Analysis ===\n")

def analyze_api_response(data, endpoint_name):
    """
    Analyze API response data.
    
    Args:
        data: API response data (list or dict)
        endpoint_name: Name of endpoint for reporting
        
    Returns:
        Dictionary with analysis results
    """
    analysis = {
        'endpoint': endpoint_name,
        'data_type': type(data).__name__,
        'analysis_time': datetime.now().isoformat()
    }
    
    if isinstance(data, dict):
        analysis['keys'] = list(data.keys())
        analysis['key_count'] = len(data)
        
        # Check for sensitive data patterns
        sensitive_keys = ['password', 'secret', 'api_key', 'token', 'credit_card']
        found_sensitive = [key for key in data.keys() if any(sk in key.lower() for sk in sensitive_keys)]
        
        if found_sensitive:
            analysis['sensitive_data'] = found_sensitive
            
    elif isinstance(data, list):
        analysis['item_count'] = len(data)
        
        if data:
            first_item = data[0]
            analysis['first_item_type'] = type(first_item).__name__
            
            if isinstance(first_item, dict):
                analysis['item_keys'] = list(first_item.keys())
                
    return analysis

# Test API response analysis
test_data_1 = {
    'user_id': 123,
    'username': 'test_user',
    'email': 'test@example.com',
    'created_at': '2023-01-15',
    'last_login': '2023-10-10'
}

test_data_2 = [
    {'id': 1, 'name': 'Product 1', 'price': 99.99},
    {'id': 2, 'name': 'Product 2', 'price': 149.99},
    {'id': 3, 'name': 'Product 3', 'price': 199.99}
]

test_data_3 = {
    'api_key': 'secret12345',
    'password': 'P@ssw0rd!',
    'database_url': 'mysql://user:pass@localhost/db'
}

print("Analyzing API Responses:")

print(f"\n1. User Data Response:")
user_analysis = analyze_api_response(test_data_1, 'User Profile')
print(f"  Type: {user_analysis['data_type']}")
print(f"  Keys: {', '.join(user_analysis['keys'])}")
print(f"  Key Count: {user_analysis['key_count']}")

print(f"\n2. Products Response:")
products_analysis = analyze_api_response(test_data_2, 'Product List')
print(f"  Type: {products_analysis['data_type']}")
print(f"  Item Count: {products_analysis['item_count']}")
print(f"  First Item Type: {products_analysis['first_item_type']}")

print(f"\n3. Configuration Response:")
config_analysis = analyze_api_response(test_data_3, 'Config')
print(f"  Type: {config_analysis['data_type']}")
print(f"  Key Count: {config_analysis['key_count']}")
if 'sensitive_data' in config_analysis:
    print(f"  Sensitive Data Found: {', '.join(config_analysis['sensitive_data'])}")

print()
print("=" * 50)
print()

# ==========================================
# 7. API Penetration Testing
# ==========================================
print("=== API Penetration Testing ===\n")

def test_api_parameters(url, params_to_test):
    """
    Test API parameter manipulation for security vulnerabilities.
    
    Args:
        url: API endpoint to test
        params_to_test: Parameters to test
        
    Returns:
        List of vulnerabilities found
    """
    vulnerabilities = []
    
    for param in params_to_test:
        print(f"\nTesting parameter: {param}")
        
        # Test for bypassing authentication
        bypass_tests = [
            ('admin', 'admin'),
            ('admin', ''),
            ('', 'admin'),
            ('1', '1')
        ]
        
        for username, password in bypass_tests:
            test_data = {param: username}
            try:
                response = requests.post(url, data=test_data)
                
                if response.status_code == 200:
                    content = response.text.lower()
                    if 'success' in content or 'welcome' in content or 'dashboard' in content:
                        vuln = {
                            'param': param,
                            'vulnerability': 'Parameter manipulation',
                            'payload': test_data,
                            'status_code': response.status_code
                        }
                        vulnerabilities.append(vuln)
                        print(f"  ⚠️  Possible authentication bypass with: {test_data}")
                        
            except Exception as e:
                print(f"  Error: {e}")
                
    return vulnerabilities

# Test parameter manipulation on login endpoint
login_url = "https://example.com/login"
params_to_test = ['username', 'password', 'role']

print("Testing API parameter manipulation...")
vulnerabilities = test_api_parameters(login_url, params_to_test)

if vulnerabilities:
    print(f"\nFound {len(vulnerabilities)} vulnerabilities:")
    for vuln in vulnerabilities:
        print(f"  - {vuln['vulnerability']}")
        print(f"    Parameter: {vuln['param']}")
        print(f"    Payload: {vuln['payload']}")
        print(f"    Status Code: {vuln['status_code']}")
else:
    print("No vulnerabilities found in parameter manipulation tests")

print()
print("=" * 50)
print()

# ==========================================
# 8. Best Practices for API Security
# ==========================================
print("=== API Security Best Practices ===\n")

api_security_best_practices = [
    "1. Use HTTPS for all API communication",
    "2. Implement proper authentication (OAuth 2.0, JWT)",
    "3. Validate and sanitize all inputs",
    "4. Use parameterized queries to prevent SQL injection",
    "5. Implement rate limiting",
    "6. Validate and escape output to prevent XSS",
    "7. Use API keys or tokens instead of credentials in URLs",
    "8. Implement proper error handling",
    "9. Use CORS appropriately",
    "10. Keep APIs updated with security patches",
    "11. Monitor API traffic for anomalies",
    "12. Use secure headers"
]

print("API Security Best Practices:")
for practice in api_security_best_practices:
    print(f"  {practice}")

print()
