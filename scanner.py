import requests
import sys

def make_request(url):
    """
    Makes a simple HTTP GET request to the given URL and prints the status code.

    Args:
        url (str): The URL to make the request to.
    """
    try:
        # Send a GET request to the URL
        # We'll set a timeout to prevent the scanner from hanging indefinitely
        response = requests.get(url, timeout=10)

        # Print the URL and its HTTP status code
        print(f"[*] URL: {url} | Status Code: {response.status_code}")

        # You can also print other information, e.g., response headers or content
        # print(f"    Headers: {response.headers}")
        # print(f"    Content Length: {len(response.text)} bytes")

    except requests.exceptions.RequestException as e:
        # Catch any request-related errors (e.g., connection errors, timeouts)
        print(f"[-] Error making request to {url}: {e}")
    except Exception as e:
        # Catch any other unexpected errors
        print(f"[-] An unexpected error occurred: {e}")

def main():
    """
    Main function to handle command-line arguments and start the scanning process.
    """
    if len(sys.argv) != 2:
        print("Usage: python scanner.py <target_url>")
        print("Example: python scanner.py https://example.com")
        sys.exit(1) # Exit with an error code

    target_url = sys.argv[1]
    print(f"[+] Starting scan for: {target_url}")
    make_request(target_url)
    print("[+] Scan finished.")

if __name__ == "__main__":
    # This ensures that main() is called only when the script is executed directly
    # and not when imported as a module.
    main()
