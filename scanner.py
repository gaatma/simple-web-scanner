import requests
import sys
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

# Define a simple XSS payload.
# This payload attempts to execute an alert box if reflected and executed.

XSS_PAYLOAD = "<script>alert('XSS')</script>"

def make_request(url):
    """
    Makes a simple HTTP GET request to the given URL and prints the status code.
    Returns the response object if successful, None otherwise.
    Args:
        url (str): The URL to make the request to.
     Returns:
        requests.Response or None: The response object if the request was successful,
                                  None if an error occurred.    
    """
    try:
        # Send a GET request to the URL
        # We'll set a timeout to prevent the scanner from hanging indefinitely
        response = requests.get(url, timeout=10)

        # Print the URL and its HTTP status code
        print(f"[*] URL: {url} | Status Code: {response.status_code}")
        return response

        # You can also print other information, e.g., response headers or content
        # print(f"    Headers: {response.headers}")
        # print(f"    Content Length: {len(response.text)} bytes")

    except requests.exceptions.RequestException as e:
        # Catch any request-related errors (e.g., connection errors, timeouts)
        print(f"[-] Error making request to {url}: {e}")
        return response
    except Exception as e:
        # Catch any other unexpected errors
        print(f"[-] An unexpected error occurred: {e}")
        return response 

def check_xss(target_url):
       
    print(f"\n[+] Checking for Reflected XSS on: {target_url}")

    # Parse the URL to get its components
    
    parsed_url = urlparse(target_url)

    # Get query parameters as a dictionary
    query_params = parse_qs(parsed_url.query)

    # If there are no query parameters, we can't easily test reflected XSS this way.
    if not query_params:
        print("    [INFO] No query parameters found in URL. Skipping reflected XSS test.")
        return   

    # Iterate through each parameter and inject the XSS payload
    for param_name in query_params:
        # Create a new dictionary for modified parameters
        modified_params = query_params.copy()
        # Inject the XSS payload into the current parameter's value
        # Note: parse_qs returns lists for values, so we replace the first item
        modified_params[param_name] = [XSS_PAYLOAD]

        # Reconstruct the query string with the injected payload
        new_query = urlencode(modified_params, doseq=True) # doseq=True handles list values correctly
        
        # Reconstruct the URL with the new query string
        # urlunparse takes a 6-tuple: (scheme, netloc, path, params, query, fragment)
        test_url_parts = list(parsed_url)
        test_url_parts[4] = new_query # Update the query part
        test_url = urlunparse(test_url_parts)

        print(f"    [*] Testing XSS with payload in '{param_name}': {test_url}")

        # Make the request with the modified URL
        response = make_request(test_url)

        if response and response.status_code == 200:
            # Check if the XSS payload is reflected in the response body
            if XSS_PAYLOAD in response.text:
                print(f"    [!!!] Potential Reflected XSS found in parameter '{param_name}'!")
                print(f"          Payload '{XSS_PAYLOAD}' reflected in response.")
            else:
                print(f"    [---] Payload not reflected in parameter '{param_name}'.")
        elif response:
            print(f"    [---] Request to {test_url} returned status code {response.status_code}. Not checking for reflection.")
        else:
            print(f"    [---] Failed to get a valid response for {test_url}.")

def main():
    """
    Main function to handle command-line arguments and start the scanning process.
    """
    if len(sys.argv) != 2:
        print("Usage: python scanner.py <target_url>")
        print("Example: python scanner.py https://example.com/search?q=test")
        sys.exit(1) # Exit with an error code

    target_url = sys.argv[1]
    print(f"[+] Starting web vulnerability scan for: {target_url}")

     # Perform a general request first (optional, but good for initial check)
     # make_request(target_url)

    # Perform XSS check
    check_xss(target_url)
   
    print("[+] Scan finished.")

if __name__ == "__main__":
    # This ensures that main() is called only when the script is executed directly
    # and not when imported as a module.
    main()
