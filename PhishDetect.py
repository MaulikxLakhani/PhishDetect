import random
import socket
import sys
import time
import requests

valid_domains = []
malicious_domains = []
phishing_db = "https://raw.githubusercontent.com/mitchellkrogza" \
              "/Phishing.Database/master/" \
              "phishing-domains-ACTIVE.txt"
phishing_filename = "phishing.db"
#  Add at least 2 VirusTotal API keys before executing.
api_keys = ["key1", "key2", "key3"]


def display_art():
    art = """

     _____  _     _     _     _____       _            _
    |  __ \| |   (_)   | |   |  __ \     | |          | |
    | |__) | |__  _ ___| |__ | |  | | ___| |_ ___  ___| |_
    |  ___/| '_ \| / __| '_ \| |  | |/ _ \ __/ _ \/ __| __|
    | |    | | | | \__ \ | | | |__| |  __/ ||  __/ (__| |_
    |_|    |_| |_|_|___/_| |_|_____/ \___|\__\___|\___|\__|      Version 2.0

    A python tool to detect phishing domains and malicious domains.
    """
    print(art)


def read_domains_from_file(file_path):
    with open(file_path, 'r') as file:
        return file.read().splitlines()


def is_valid_domain(domain):
    try:
        socket.gethostbyname(domain)  # Use socket to perform DNS resolution
        return True
    except socket.gaierror:
        return False
    except Exception as e:
        print(f"Error: {e}")


def check_virustotal(domain):
    selected_api_key = random.choice(api_keys)
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/resolutions?limit=1"
    headers = {
        "accept": "application/json",
        "Content-Type": "application/json",
        "X-Tool": "vt-ui-main",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/120.0.6099.71 Safari/537.36",
        "Accept-Ianguage": "en-US,en;q=0.9,es;q=0.8",
        # update your VirusTotal API key before executing.
        "x-apikey": selected_api_key
    }

    try:
        time.sleep(0.2)
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Check for any request errors
        json_data = response.json()

        malicious_count = json_data["data"][0]["attributes"]["host_name_last_analysis_stats"]["malicious"]
        if malicious_count >= 5:
            print(f"Malicious domain: {domain}")
            malicious_domains.append(domain)
        else:
            pass
            # print(f"Not a malicious domain: {domain}")

        pass
    except requests.exceptions.RequestException as e:
        print(f"Error checking domain {domain}: {e}")


def update_phishing_db():
    try:
        session = requests.session()
        r = session.get(phishing_db, stream=True)
        total_size = int(r.headers.get("content-length", 0))
        total_size_mb = round(float(total_size / 1024 / 1024), 2)

        if total_size_mb == 0:
            print("[ERROR] File not found or empty! Exiting...\n")
            exit(-1)

        # print("[*] Database updated: ", total_size_mb, "MB")
        print("[*] Database updated: ")

        data = r.content
        r.close()
        session.close()

        with open(phishing_filename, "wb") as f:
            f.write(data)

    except requests.exceptions.ConnectionError:
        print("Error connecting to the server. Exiting...\n")
        exit(-1)

    return True


def url_contains(domain, phishing):
    return domain in phishing


def check_phishing_db():
    with open('domains.txt', mode='r') as f_domains:
        for domain in f_domains:
            domain = domain.strip().lower()

            with open(phishing_filename, mode='r') as f_phishing:
                for site in f_phishing:
                    phishing_site = site.strip().lower()

                    if url_contains(domain, phishing_site):
                        print("GitHub DB Malicious domain found: ", domain)
                        malicious_domains.append(domain)
    pass
    # print("\n Malicious domains: ", malicious_domains, "\n")


def export_malicious_domains():
    malicious_domains.sort()
    print(malicious_domains)
    with open('result.txt', 'w') as result_file:
        for domain in malicious_domains:
            result_file.write(domain + '\n')

    return malicious_domains


def main():
    display_art()
    try:
        if len(sys.argv) != 2:
            raise ValueError("Invalid input. Usage: python PhishDetect.py <domains.txt>")

        file_path = sys.argv[1]
        domains = read_domains_from_file(file_path)

        if not domains:
            raise ValueError("No domains found in the file.")

        for domain in domains:
            if len(domain) > 4:  # Basic domain length check
                if is_valid_domain(domain):
                    # valid_domains.append({domain})
                    check_virustotal(domain)
                else:
                    pass
                    # print(f"Skipping invalid domain: {domain} \n")
        pass
        # Update GitHub Phishing Database
        update_phishing_db()
        # Check active domains in GitHub Phishing DB
        check_phishing_db()
        #  export_results()

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
    if not malicious_domains:
        print("No malicious domains detected.")
    else:
        pass
        export_malicious_domains()
        print(f"\n Matching phishing domains exported to 'result.txt'.")
