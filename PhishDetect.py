import sys
import requests

def check_malicious_status(domain):
    url = f"https://www.virustotal.com/ui/domains/{domain}/resolutions?limit=1"
    headers = {
        "accept": "application/json",
        "Content-Type": "application/json",
        "X-Tool": "vt-ui-main",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/120.0.6099.71 Safari/537.36",
        "X-Vt-Anti-Abuse-Header": "MTAxNTIzMDUwNjMtWkc5dWRDQmlaU0JsZG1scy0xNzA1NDc0NTI4LjUyOQ==",
        "Accept-Ianguage": "en-US,en;q=0.9,es;q=0.8"
    }
    response = requests.get(url, headers=headers)
    response.raise_for_status()  # Check for any request errors
    json_data = response.json()
    malicious_count = json_data["data"][0]["attributes"]["host_name_last_analysis_stats"]["malicious"]

    print(f"Domain Name: {domain}")
    if malicious_count >= 5:
        print("Malicious domain")
    else:
        print("NOT a malicious domain.")
    print()

def main():
    try:
        # Input validation
        if len(sys.argv) != 2:
            raise ValueError("Invalid input. Usage: python script.py <file_path>")

        file_path = sys.argv[1]

        with open(file_path, 'r') as file:
            domains = file.read().splitlines()

        if not domains:
            raise ValueError("No domains found in the file.")

        for domain in domains:
            if len(domain) > 4:  # Basic domain length check
                check_malicious_status(domain)
            else:
                print(f"Invalid domain name: {domain} (skipping)")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
