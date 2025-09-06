# xss_checker.py

import argparse
import requests
from urllib.parse import quote_plus
from collections import defaultdict
from bs4 import BeautifulSoup

# A helpful library for making HTTP requests.
# To install: pip install requests
# For parsing HTML to check for payloads.
# To install: pip install beautifulsoup4

def check_xss_vulnerability(url, input_field_name):
    """
    Tests a website's search input field for XSS vulnerabilities by
    checking how special characters and tags are handled.
    """
    # A dictionary to store the results of our tests
    results = defaultdict(dict)

    # Payloads to test. These include special characters and a basic script tag.
    payloads = {
        'single_quote': "'",
        'double_quote': '"',
        'less_than': "<",
        'greater_than': ">",
        'ampersand': "&",
        'slash': "/",
        'script_tag': "<script>alert('XSS')</script>"
    }

    print(f"[*] Testing URL: {url}")
    print(f"[*] Target Input Field: '{input_field_name}'")
    print("-" * 50)

    # Loop through each payload and test the input field
    for name, payload in payloads.items():
        print(f"[*] Testing payload: {name} ('{payload}')")

        # The data to be sent in the POST request. The key is the input field's 'name' attribute.
        data = {input_field_name: payload}

        try:
            # We use a POST request, as that's a common method for search forms.
            # You might need to change this to `requests.get` if the form uses GET.
            response = requests.post(url, data=data, timeout=10)
            response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)

            # Use BeautifulSoup to parse the HTML and find the injected payload
            soup = BeautifulSoup(response.text, 'html.parser')

            # We'll check the raw HTML to see if the payload is present
            raw_html = str(soup)

            # Check for the raw payload first
            if payload in raw_html:
                results[name]['status'] = 'Vulnerable'
                results[name]['message'] = 'The payload was found unencoded in the response.'
            else:
                # If not found, check for common encoded versions
                encoded_html_entity = payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;').replace('&', '&amp;')
                encoded_url = quote_plus(payload)
                
                if encoded_html_entity in raw_html:
                    results[name]['status'] = 'Encoded'
                    results[name]['message'] = f"The payload was HTML-encoded as '{encoded_html_entity}'."
                elif encoded_url in raw_html:
                    results[name]['status'] = 'Encoded'
                    results[name]['message'] = f"The payload was URL-encoded as '{encoded_url}'."
                else:
                    results[name]['status'] = 'Filtered'
                    results[name]['message'] = 'The payload could not be found or was completely filtered.'

            print(f"   -> Result: {results[name]['status']}")
            print(f"      Details: {results[name]['message']}\n")

        except requests.exceptions.RequestException as e:
            print(f"   -> An error occurred: {e}")
            break

    # Final summary
    print("=" * 50)
    print("XSS Scan Summary")
    print("=" * 50)
    for name, result in results.items():
        print(f"Payload '{name}': {result.get('status', 'Error')}")
        if 'message' in result:
            print(f"  - {result['message']}")
    
    print("\nScan complete.")


def main():
    """
    Main function to parse command-line arguments and run the checker.
    """
    parser = argparse.ArgumentParser(description="XSS Vulnerability Checker. Tests a specified website's search box for common encoding issues.")
    parser.add_argument("url", help="The full URL of the website to test (e.g., http://example.com/search)")
    parser.add_argument("input_field", help="The 'name' attribute of the search box input field (e.g., 'q' or 'search_query')")

    args = parser.parse_args()

    check_xss_vulnerability(args.url, args.input_field)

if __name__ == "__main__":
    main()
