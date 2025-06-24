import socket
import requests
import argparse
import time
import sys
import os

# Suppress insecure request warnings, especially useful when dealing with
# self-signed certificates on target servers during testing.
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# --- Utility Functions ---

def print_banner(text):
    """
    Prints a formatted banner for module separation and clarity.

    Args:
        text (str): The text to display in the banner.
    """
    print("\n" + "="*70)
    print(f"  {text.upper():^66}  ")
    print("="*70 + "\n")

def print_section_header(text):
    """
    Prints a smaller header for subsections within modules.

    Args:
        text (str): The text for the section header.
    """
    print(f"\n--- {text} ---")

def print_result(message):
    """Prints a successful result or finding."""
    print(f"[+] {message}")

def print_info(message):
    """Prints an informational message."""
    print(f"[INFO] {message}")

def print_error(message):
    """Prints an error message."""
    print(f"[-] {message}")

# --- Module 1: Port Scanner ---

def port_scanner(target_host, start_port, end_port, timeout=1.0):
    """
    Scans a target host for open TCP ports within a specified range.

    This module attempts to establish a TCP connection to each port.
    If the connection is successful, the port is considered open.

    Args:
        target_host (str): The IP address or hostname of the target.
        start_port (int): The starting port number for the scan (inclusive).
        end_port (int): The ending port number for the scan (inclusive).
        timeout (float): The maximum time in seconds to wait for a connection attempt.
                         A lower timeout makes the scan faster but might miss some
                         slow-responding open ports.
    """
    print_banner("Port Scanner")
    print_info(f"Scanning {target_host} for open ports from {start_port} to {end_port}...")
    print_info(f"Connection timeout set to {timeout} seconds per port.")

    open_ports = []
    
    # Basic validation for port range
    if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port):
        print_error("Invalid port range. Ports must be between 1 and 65535, and start_port <= end_port.")
        return

    try:
        # Resolve hostname to IP address once to avoid repeated lookups
        target_ip = socket.gethostbyname(target_host)
        print_info(f"Resolved {target_host} to {target_ip}")
    except socket.gaierror:
        print_error(f"Hostname could not be resolved: {target_host}. Please check the hostname or IP address.")
        return

    print_section_header("Scan Progress")
    for port in range(start_port, end_port + 1):
        try:
            # Create a TCP socket object (AF_INET for IPv4, SOCK_STREAM for TCP)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout) # Set a timeout for the connection attempt

            # Attempt to connect to the target host and port
            # connect_ex returns 0 on success, or an error indicator otherwise.
            result = s.connect_ex((target_ip, port))

            if result == 0:
                print_result(f"Port {port}: OPEN")
                open_ports.append(port)
            else:
                # Print progress for closed/filtered ports, overwriting the line
                sys.stdout.write(f"Scanning port {port} of {end_port}...\r")
                sys.stdout.flush() # Ensure it's written immediately
            s.close() # Close the socket after each attempt
        except ConnectionRefusedError:
            # This is often handled by connect_ex returning an error, but good to catch explicitly
            pass
        except socket.timeout:
            # This means the port filtered or dropped the connection
            sys.stdout.write(f"Scanning port {port} of {end_port}... (Timeout)\r")
            sys.stdout.flush()
        except socket.error as e:
            print_error(f"Could not connect to port {port}: {e}")
            break # Break on general socket errors that might indicate broader issues
        except Exception as e:
            print_error(f"An unexpected error occurred during scan of port {port}: {e}")
            break # Break on other unexpected errors
    
    # Print a newline to ensure subsequent output starts on a new line after progress updates
    print("\n" + "="*70)
    print_section_header("Scan Summary")
    if open_ports:
        print_result(f"Scan complete. Found {len(open_ports)} open ports.")
        print("Open Ports:", ', '.join(map(str, sorted(open_ports))))
    else:
        print_info("Scan complete. No open ports found in the specified range.")
    print("="*70)

# --- Module 2: Simple HTTP Login Brute-Forcer ---

def http_bruteforce(url, username_field, password_field, wordlist_path, success_string, username, method='POST', delay=0.1):
    """
    Attempts to brute-force a web login form using a given username and a password wordlist.

    This module sends HTTP requests (GET or POST) to a target URL,
    injecting passwords from a wordlist. It determines login success
    by checking for the absence of a specified 'success_string' in the
    HTTP response body.

    Args:
        url (str): The full URL of the login form (e.g., 'http://example.com/login.php').
        username_field (str): The 'name' attribute of the username input field in the HTML form.
        password_field (str): The 'name' attribute of the password input field in the HTML form.
        wordlist_path (str): The file path to the password wordlist (one password per line).
        success_string (str): A string that is *NOT* expected in the response body if
                              login is successful (e.g., 'Invalid credentials', 'Login failed').
                              This check is case-insensitive.
        username (str): The fixed username to brute-force against.
        method (str): The HTTP method to use for the request ('GET' or 'POST'). Defaults to 'POST'.
        delay (float): The time in seconds to wait between each request to avoid
                       rate limiting or overwhelming the server. Defaults to 0.1.
    """
    print_banner("HTTP Login Brute-Forcer")
    print_info(f"Target URL: {url}")
    print_info(f"Username to test: '{username}'")
    print_info(f"Username field name: '{username_field}'")
    print_info(f"Password field name: '{password_field}'")
    print_info(f"Wordlist: '{wordlist_path}'")
    print_info(f"HTTP Method: '{method.upper()}'")
    print_info(f"Delay between requests: {delay} seconds")
    print_info(f"Login success is determined by the ABSENCE of: '{success_string}' (case-insensitive)")

    if not os.path.exists(wordlist_path):
        print_error(f"Wordlist file not found at '{wordlist_path}'. Please check the path.")
        return

    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            # Read passwords, strip whitespace, and filter out empty lines
            passwords = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print_error(f"Error reading wordlist file: {e}")
        return

    if not passwords:
        print_error("Wordlist is empty after reading. Aborting brute-force.")
        return
    else:
        print_info(f"Loaded {len(passwords)} passwords from wordlist.")

    session = requests.Session()
    # Set a custom User-Agent to identify the scanner
    session.headers.update({'User-Agent': 'PT-Toolkit/1.0 (Python Brute-Forcer)'})

    found_credentials = False
    print_section_header("Brute-Force Progress")
    for i, password in enumerate(passwords):
        # Prepare the data payload for the request
        data = {
            username_field: username,
            password_field: password
        }
        
        # Print progress on the same line
        sys.stdout.write(f"[{i+1}/{len(passwords)}] Trying password: {password:<30}\r")
        sys.stdout.flush()

        try:
            if method.upper() == 'POST':
                response = session.post(url, data=data, timeout=15, verify=False) # 15s timeout
            elif method.upper() == 'GET':
                response = session.get(url, params=data, timeout=15, verify=False)
            else:
                print_error(f"\nUnsupported HTTP method: '{method}'. Only 'GET' and 'POST' are supported.")
                return

            # Check if the 'success_string' is NOT in the response text (case-insensitive)
            if success_string.lower() not in response.text.lower():
                print_result(f"\nSUCCESS! Found credentials:")
                print_result(f"  URL: {url}")
                print_result(f"  Username: '{username}'")
                print_result(f"  Password: '{password}'")
                found_credentials = True
                break # Stop after finding the first valid credential
        
        except requests.exceptions.ConnectionError:
            print_error(f"\nConnection Error: Could not connect to {url}. Check URL or network.")
            found_credentials = False # Indicate that the scan was interrupted due to connection
            break
        except requests.exceptions.Timeout:
            print_error(f"\nRequest timed out for password: '{password}'. Target might be slow or blocking.")
            continue # Continue with next password if timeout occurs
        except requests.exceptions.TooManyRedirects:
            print_error(f"\nToo many redirects for password: '{password}'. Check URL or target behavior.")
            continue
        except requests.exceptions.RequestException as e:
            print_error(f"\nAn HTTP request error occurred for password '{password}': {e}")
            continue
        except Exception as e:
            print_error(f"\nAn unexpected error occurred during request for password '{password}': {e}")
            continue
        
        # Introduce a delay between requests
        time.sleep(delay)

    # Print a newline to ensure subsequent output starts on a new line after progress updates
    print("\n" + "="*70)
    print_section_header("Brute-Force Summary")
    if not found_credentials:
        print_info("Brute-force complete. No valid credentials found with the provided wordlist.")
    print("="*70)


# --- Main Function and Argument Parsing ---

def main():
    """
    Main function to parse command-line arguments and execute the selected module.
    """
    parser = argparse.ArgumentParser(
        description="A simple Penetration Testing Toolkit with modular capabilities.\n"
                    "Use --module to select a specific tool.",
        formatter_class=argparse.RawTextHelpFormatter # Allows for newlines in help messages
    )

    parser.add_argument(
        '--module',
        choices=['portscan', 'bruteforce'],
        required=True,
        help="Specify the penetration testing module to run:\n"
             "  portscan   - Scans for open TCP ports on a target host.\n"
             "  bruteforce - Attempts to brute-force a web login form."
    )

    # --- Arguments for Port Scanner ---
    portscan_group = parser.add_argument_group('Port Scanner Arguments')
    portscan_group.add_argument(
        '--host',
        help="Target host IP address or hostname for port scanning (e.g., '127.0.0.1', 'scanme.nmap.org')."
    )
    portscan_group.add_argument(
        '--start-port',
        type=int,
        help="Starting port number for the scan (e.g., 1)."
    )
    portscan_group.add_argument(
        '--end-port',
        type=int,
        help="Ending port number for the scan (e.g., 1024, 65535)."
    )
    portscan_group.add_argument(
        '--timeout',
        type=float,
        default=1.0,
        help="Socket timeout in seconds for port scan connection attempts (default: 1.0)."
    )

    # --- Arguments for HTTP Brute-Forcer ---
    bruteforce_group = parser.add_argument_group('HTTP Brute-Forcer Arguments')
    bruteforce_group.add_argument(
        '--url',
        help="Target URL of the login form (e.g., 'http://localhost/login.php')."
    )
    bruteforce_group.add_argument(
        '--user-field',
        help="The 'name' attribute of the username input field in the HTML form (e.g., 'username', 'user_id')."
    )
    bruteforce_group.add_argument(
        '--pass-field',
        help="The 'name' attribute of the password input field in the HTML form (e.g., 'password', 'pass')."
    )
    bruteforce_group.add_argument(
        '--wordlist',
        help="Path to the password wordlist file (one password per line)."
    )
    bruteforce_group.add_argument(
        '--success-string',
        help="A string that is *NOT* expected in the response body if login is successful (e.g., 'Invalid credentials', 'Login failed', 'Authentication failed')."
    )
    bruteforce_group.add_argument(
        '--username',
        help="The fixed username to brute-force against (e.g., 'admin', 'testuser')."
    )
    bruteforce_group.add_argument(
        '--method',
        choices=['GET', 'POST'],
        default='POST',
        help="HTTP method for the brute-force request (default: POST)."
    )
    bruteforce_group.add_argument(
        '--delay',
        type=float,
        default=0.1,
        help="Delay between requests in seconds for brute-forcer (default: 0.1). Adjust to avoid rate limiting."
    )

    args = parser.parse_args()

    # Execute the selected module based on command-line arguments
    if args.module == 'portscan':
        # Check if all required arguments for portscan are provided
        if not all([args.host, args.start_port is not None, args.end_port is not None]):
            parser.error("--host, --start-port, and --end-port are required for the 'portscan' module.")
        port_scanner(args.host, args.start_port, args.end_port, args.timeout)
    
    elif args.module == 'bruteforce':
        # Check if all required arguments for bruteforce are provided
        if not all([args.url, args.user_field, args.pass_field, args.wordlist, args.success_string, args.username]):
            parser.error("--url, --user-field, --pass-field, --wordlist, --success-string, and --username are required for the 'bruteforce' module.")
        http_bruteforce(args.url, args.user_field, args.pass_field, args.wordlist, args.success_string, args.username, args.method, args.delay)

# Entry point of the script
if __name__ == "__main__":
    main()
