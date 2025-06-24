import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import argparse
import sys

# Suppress insecure request warnings for self-signed certificates
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class WebVulnerabilityScanner:
    def __init__(self, target_url, crawl_depth=1):
        """
        Initializes the WebVulnerabilityScanner.

        Args:
            target_url (str): The base URL of the web application to scan.
            crawl_depth (int): The maximum depth to crawl links from the initial URL.
        """
        self.target_url = target_url
        self.crawl_depth = crawl_depth
        self.visited_urls = set()
        self.vulnerabilities_found = {
            "SQL Injection": [],
            "XSS": []
        }
        # Common payloads for demonstration purposes
        self.sql_injection_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "\" OR \"1\"=\"1",
            "1' UNION SELECT NULL, NULL, NULL--", # Example for union-based
            "admin'--",
            "1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE(('a'),10)", # Blind SQLi (time-based)
        ]
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "\" onmouseover=\"alert('XSS')\" foo=\"",
            "<svg/onload=alert('XSS')>",
        ]
        # Common SQL error messages to look for
        self.sql_error_messages = [
            "SQL syntax",
            "mysql_fetch_array()",
            "You have an error in your SQL syntax",
            "Warning: mysql_",
            "unclosed quotation mark",
            "Microsoft OLE DB Provider for ODBC Drivers error",
            "DB_QUERY_ERROR",
            "SQLSTATE",
            "ORA-", # Oracle errors
            "PgSqlException", # PostgreSQL errors
        ]
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WebVulnScanner/1.0 (Python)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive'
        })

    def _log_info(self, message):
        """Prints an informational message."""
        print(f"[INFO] {message}")

    def _log_success(self, message):
        """Prints a success message for vulnerability findings."""
        print(f"[+] {message}")

    def _log_error(self, message):
        """Prints an error message."""
        print(f"[-] {message}")

    def _get_page_content(self, url):
        """
        Fetches the content of a given URL.

        Args:
            url (str): The URL to fetch.

        Returns:
            str: The HTML content of the page, or None if an error occurs.
        """
        try:
            self._log_info(f"Fetching URL: {url}")
            response = self.session.get(url, timeout=10, verify=False)
            response.raise_for_status()  # Raise an HTTPError for bad responses (4xx or 5xx)
            return response.text
        except requests.exceptions.RequestException as e:
            self._log_error(f"Failed to fetch {url}: {e}")
            return None

    def _find_forms(self, soup, current_url):
        """
        Finds and parses HTML forms from a BeautifulSoup object.

        Args:
            soup (BeautifulSoup): The parsed HTML content.
            current_url (str): The URL of the page being parsed, used for resolving relative paths.

        Returns:
            list: A list of dictionaries, each representing a form with its action, method, and input fields.
        """
        forms = []
        for form_tag in soup.find_all('form'):
            form_details = {}
            action = form_tag.get('action')
            method = form_tag.get('method', 'get').lower() # Default to 'get' if not specified
            
            # Resolve relative URLs
            form_details['action'] = urljoin(current_url, action) if action else current_url
            form_details['method'] = method
            form_details['inputs'] = []

            for input_tag in form_tag.find_all(['input', 'textarea', 'select']):
                input_name = input_tag.get('name')
                input_type = input_tag.get('type', 'text') # Default to 'text' if not specified
                input_value = input_tag.get('value', '')
                if input_name: # Only add inputs with a name attribute
                    form_details['inputs'].append({'name': input_name, 'type': input_type, 'value': input_value})
            forms.append(form_details)
        return forms

    def _find_links(self, soup, base_url):
        """
        Finds and resolves all unique links on a page.

        Args:
            soup (BeautifulSoup): The parsed HTML content.
            base_url (str): The base URL of the page being parsed, for resolving relative links.

        Returns:
            set: A set of absolute URLs found on the page, filtered to stay within the target domain.
        """
        links = set()
        base_netloc = urlparse(base_url).netloc
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            full_url = urljoin(base_url, href)
            parsed_full_url = urlparse(full_url)

            # Filter out non-HTTP/HTTPS links and external domains
            if parsed_full_url.scheme in ['http', 'https'] and parsed_full_url.netloc == base_netloc:
                # Remove fragment identifiers (e.g., #section)
                cleaned_url = parsed_full_url._replace(fragment="").geturl()
                links.add(cleaned_url)
        return links

    def _check_sql_error(self, response_text):
        """
        Checks if the response text contains common SQL error messages.

        Args:
            response_text (str): The HTML content of the response.

        Returns:
            bool: True if an SQL error message is found, False otherwise.
        """
        for error_msg in self.sql_error_messages:
            if error_msg.lower() in response_text.lower():
                return True
        return False

    def _scan_sql_injection(self, url, method, data=None):
        """
        Tests for SQL Injection vulnerability on a given URL/form.

        Args:
            url (str): The URL to test.
            method (str): The HTTP method ('get' or 'post').
            data (dict, optional): The dictionary of parameters to inject into (for POST requests).
                                   If None, assumes GET parameters or no parameters.
        """
        self._log_info(f"Testing SQL Injection for {url} (Method: {method.upper()})")

        # Handle GET requests (URL parameters)
        if method == 'get':
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            if not query_params:
                # No GET parameters to inject, skip
                return

            original_query = parsed_url.query
            for param_name, param_values in query_params.items():
                original_value = param_values[0] # Take the first value if multiple

                for payload in self.sql_injection_payloads:
                    test_params = query_params.copy()
                    test_params[param_name] = original_value + payload
                    
                    # Reconstruct the URL with the injected payload
                    injected_query = urlencode(test_params, doseq=True)
                    test_url = parsed_url._replace(query=injected_query).geturl()

                    response_text = self._get_page_content(test_url)
                    if response_text and self._check_sql_error(response_text):
                        self.vulnerabilities_found["SQL Injection"].append(
                            f"Potential SQL Injection via GET parameter '{param_name}' at {test_url} with payload: '{payload}'"
                        )
                        self._log_success(f"Potential SQL Injection found at {test_url} (GET parameter: {param_name}) with payload: {payload}")
                    
                    # Restore original value for next payload
                    test_params[param_name] = original_value

        # Handle POST requests (form data)
        elif method == 'post' and data:
            for input_field in data['inputs']:
                input_name = input_field['name']
                input_type = input_field['type']

                if input_type in ['text', 'search', 'email', 'password', 'url', 'textarea']:
                    original_value = input_field.get('value', '')
                    for payload in self.sql_injection_payloads:
                        test_data = {i['name']: i['value'] for i in data['inputs']}
                        test_data[input_name] = original_value + payload

                        try:
                            self._log_info(f"Sending POST request to {url} with payload for {input_name}: {payload[:50]}...")
                            response = self.session.post(url, data=test_data, timeout=10, verify=False)
                            response.raise_for_status()
                            if self._check_sql_error(response.text):
                                self.vulnerabilities_found["SQL Injection"].append(
                                    f"Potential SQL Injection via POST parameter '{input_name}' at {url} with payload: '{payload}'"
                                )
                                self._log_success(f"Potential SQL Injection found at {url} (POST parameter: {input_name}) with payload: {payload}")
                        except requests.exceptions.RequestException as e:
                            self._log_error(f"Failed POST request to {url} with payload '{payload}' for '{input_name}': {e}")


    def _scan_xss(self, url, method, data=None):
        """
        Tests for Cross-Site Scripting (XSS) vulnerability on a given URL/form.

        Args:
            url (str): The URL to test.
            method (str): The HTTP method ('get' or 'post').
            data (dict, optional): The dictionary of parameters to inject into (for POST requests).
        """
        self._log_info(f"Testing XSS for {url} (Method: {method.upper()})")

        # Handle GET requests (URL parameters)
        if method == 'get':
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            if not query_params:
                # No GET parameters to inject, skip
                return
            
            original_query = parsed_url.query
            for param_name, param_values in query_params.items():
                original_value = param_values[0]

                for payload in self.xss_payloads:
                    test_params = query_params.copy()
                    test_params[param_name] = payload
                    
                    injected_query = urlencode(test_params, doseq=True)
                    test_url = parsed_url._replace(query=injected_query).geturl()

                    response_text = self._get_page_content(test_url)
                    if response_text and payload in response_text:
                        # Simple check: if payload is directly reflected without encoding
                        self.vulnerabilities_found["XSS"].append(
                            f"Potential XSS via GET parameter '{param_name}' at {test_url} with payload: '{payload}'"
                        )
                        self._log_success(f"Potential XSS found at {test_url} (GET parameter: {param_name}) with payload: {payload}")
                    
                    # Restore original value for next payload
                    test_params[param_name] = original_value


        # Handle POST requests (form data)
        elif method == 'post' and data:
            for input_field in data['inputs']:
                input_name = input_field['name']
                input_type = input_field['type']

                if input_type in ['text', 'search', 'email', 'password', 'url', 'textarea']:
                    original_value = input_field.get('value', '')
                    for payload in self.xss_payloads:
                        test_data = {i['name']: i['value'] for i in data['inputs']}
                        test_data[input_name] = payload

                        try:
                            self._log_info(f"Sending POST request to {url} with payload for {input_name}: {payload[:50]}...")
                            response = self.session.post(url, data=test_data, timeout=10, verify=False)
                            response.raise_for_status()
                            if payload in response.text:
                                # Simple check: if payload is directly reflected without encoding
                                self.vulnerabilities_found["XSS"].append(
                                    f"Potential XSS via POST parameter '{input_name}' at {url} with payload: '{payload}'"
                                )
                                self._log_success(f"Potential XSS found at {url} (POST parameter: {input_name}) with payload: {payload}")
                        except requests.exceptions.RequestException as e:
                            self._log_error(f"Failed POST request to {url} with payload '{payload}' for '{input_name}': {e}")


    def crawl_and_scan(self, url, current_depth):
        """
        Recursively crawls and scans a given URL for vulnerabilities.

        Args:
            url (str): The URL to crawl and scan.
            current_depth (int): The current crawling depth.
        """
        if url in self.visited_urls or current_depth > self.crawl_depth:
            return

        self.visited_urls.add(url)
        self._log_info(f"Scanning URL: {url} (Depth: {current_depth}/{self.crawl_depth})")

        html_content = self._get_page_content(url)
        if not html_content:
            return

        soup = BeautifulSoup(html_content, 'html.parser')

        # Scan GET parameters in the current URL
        parsed_url = urlparse(url)
        if parsed_url.query:
            self._scan_sql_injection(url, 'get')
            self._scan_xss(url, 'get')

        # Find and scan forms
        forms = self._find_forms(soup, url)
        for form in forms:
            self._log_info(f"Found form: Action='{form['action']}', Method='{form['method']}'")
            self._scan_sql_injection(form['action'], form['method'], data=form)
            self._scan_xss(form['action'], form['method'], data=form)

        # Find and crawl links
        if current_depth < self.crawl_depth:
            links = self._find_links(soup, url)
            for link in links:
                self.crawl_and_scan(link, current_depth + 1)

    def scan(self):
        """
        Starts the web application scan from the target URL.
        """
        self._log_info(f"Starting scan for: {self.target_url}")
        self.crawl_and_scan(self.target_url, 0)
        self._log_info("Scan complete. Displaying results:")
        self.print_results()

    def print_results(self):
        """
        Prints a summary of found vulnerabilities.
        """
        print("\n" + "="*50)
        print("           SCAN RESULTS           ")
        print("="*50)

        total_vulnerabilities = 0
        for vuln_type, findings in self.vulnerabilities_found.items():
            if findings:
                print(f"\n--- {vuln_type} ({len(findings)} found) ---")
                for finding in findings:
                    print(f"  - {finding}")
                total_vulnerabilities += len(findings)

        print("\n" + "="*50)
        if total_vulnerabilities == 0:
            print("         No vulnerabilities found!         ")
        else:
            print(f"Total vulnerabilities found: {total_vulnerabilities}")
        print("="*50 + "\n")

def main():
    parser = argparse.ArgumentParser(
        description="Basic Web Application Vulnerability Scanner."
    )
    parser.add_argument(
        "url",
        help="The target URL of the web application to scan (e.g., http://example.com)"
    )
    parser.add_argument(
        "-d", "--depth",
        type=int,
        default=1,
        help="Crawling depth (default: 1 - only current page and direct links)"
    )

    args = parser.parse_args()

    # Basic URL validation
    if not args.url.startswith(('http://', 'https://')):
        print("Error: URL must start with http:// or https://")
        sys.exit(1)

    scanner = WebVulnerabilityScanner(args.url, args.depth)
    scanner.scan()

if __name__ == "__main__":
    main()
