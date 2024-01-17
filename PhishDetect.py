import sys
import time
import requests

def display_art():
    art = """
    
     _____  _     _     _     _____       _            _   
    |  __ \| |   (_)   | |   |  __ \     | |          | |  
    | |__) | |__  _ ___| |__ | |  | | ___| |_ ___  ___| |_ 
    |  ___/| '_ \| / __| '_ \| |  | |/ _ \ __/ _ \/ __| __|
    | |    | | | | \__ \ | | | |__| |  __/ ||  __/ (__| |_ 
    |_|    |_| |_|_|___/_| |_|_____/ \___|\__\___|\___|\__|      Version 1.0
                                                                                                                                                                
    A python tool to detect phishing domains and malicious domains.
    """
    print(art)

def check_malicious_status(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/resolutions?limit=1"
    headers = {
        "accept": "application/json",
        "Content-Type": "application/json",
        "X-Tool": "vt-ui-main",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/120.0.6099.71 Safari/537.36",
        "Accept-Ianguage": "en-US,en;q=0.9,es;q=0.8",
        # update your VirusTotal API key before executing.
        "x-apikey": "b06ad5679225334e4d427cf2307f43347c35e42c433d87e9f3f0d0b879439d9a"
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Check for any request errors

        json_data = response.json()
        malicious_count = json_data["data"][0]["attributes"]["host_name_last_analysis_stats"]["malicious"]

        print(f"Domain Name: {domain}")
        if malicious_count >= 5:
            print(f"Malicious domain (Occurrences: {malicious_count})")
        else:
            print("Doesn't seem like a malicious domain.")
        print()

    except requests.exceptions.RequestException as e:
        print(f"Error checking domain {domain}: {e}")


def read_domains_from_file(file_path):
    with open(file_path, 'r') as file:
        return file.read().splitlines()


def main():
    display_art()
    try:
        if len(sys.argv) != 2:
            raise ValueError("Invalid input. Usage: python script.py <file_path>")

        file_path = sys.argv[1]
        domains = read_domains_from_file(file_path)

        if not domains:
            raise ValueError("No domains found in the file.")

        for domain in domains:
            if len(domain) > 4:  # Basic domain length check
                check_malicious_status(domain)
                time.sleep(0.25)
            else:
                print(f"Invalid domain name: {domain} (skipping)")

    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()
