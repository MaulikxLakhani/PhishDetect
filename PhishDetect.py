import os
import random
import socket
import sys
import time
import requests

# Global Constants
malicious_domains = []
gh_phishing_feed = "https://raw.githubusercontent.com/mitchellkrogza" \
                   "/Phishing.Database/master/" \
                   "phishing-domains-ACTIVE.txt"
gh_phishing_db = "gh_phishing.db"
open_phish_feed = "https://openphish.com/feed.txt"
open_phish_db = "open_phish.db"
discord_phishing_feed = "https://raw.githubusercontent.com/MaulikxLakhani/PhishDetect/main/discord-phishing-domains.txt"
discord_phishing_db = "discord_phishing.db"


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


def read_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            # return file.read().splitlines()
            return [line.lower() for line in file.read().splitlines()]
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None
    except Exception as e:
        print(f"Unable to read file: {e}")
        return None


def is_valid_domain(domain):
    try:
        socket.gethostbyname(domain)  # Use socket to perform DNS resolution
        return True
    except socket.gaierror:
        return False
    except UnicodeError:
        print(f"Invalid domain, name too long, skipping...")
    except Exception as e:
        print(f"Error: {e}")


def check_virustotal(domain):
    try:
        vt_api_keys = read_from_file(sys.argv[2])
        selected_api_key = random.choice(vt_api_keys)
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/resolutions?limit=1"
        headers = {
            "accept": "application/json",
            "Content-Type": "application/json",
            "X-Tool": "vt-ui-main",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/120.0.6099.71 Safari/537.36",
            "Accept-Ianguage": "en-US,en;q=0.9,es;q=0.8",
            # Add at least 2 VirusTotal API keys in virustotal.txt before executing.
            "x-apikey": selected_api_key
        }
        time.sleep(0.2)
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Check for any request errors
        json_data = response.json()
        malicious_count = json_data["data"][0]["attributes"]["host_name_last_analysis_stats"]["malicious"]
        if malicious_count > 3:
            print(f"VirusTotal:", domain)
            malicious_domains.append(domain)

    except requests.exceptions.RequestException as e:
        print(f"VirusTotal: Error checking {domain}: {e}")

    except Exception as e:
        print(f"Skipping VirusTotal: {e}")


def url_contains(domain, phishing):
    return domain in phishing


def get_phishing_db(feed_url, feed_name, db_name):
    try:
        session = requests.session()
        r = session.get(feed_url, stream=True)
        total_size = int(r.headers.get("content-length", 0))
        total_size_mb = round(float(total_size / 1024 / 1024), 2)

        if total_size_mb == 0:
            print("Error fetching ", feed_name, " . Checking other sources...\n")
        else:
            print(feed_name, "database updated. ")

        data = r.content
        r.close()
        session.close()
        with open(db_name, "wb") as f:
            f.write(data)

    except requests.exceptions.ConnectionError:
        print("Error connecting to the server. Exiting...\n")

    return True


def check_phishing_db(file_name, feed_name, db_name):
    with open(file_name, mode='r') as f_domains:
        for domain in f_domains:
            domain = domain.strip().lower()

            with open(db_name, mode='r') as f_phishing:
                for site in f_phishing:
                    phishing_site = site.strip().lower()
                    if url_contains(domain, phishing_site):
                        print(feed_name, ":", domain)
                        malicious_domains.append(domain)

    # print("\n Malicious domains: ", malicious_domains, "\n")
    pass


def check_quad9(domain):
    url = f"https://api.quad9.net/search/{domain}"
    headers = {
        'Host': 'api.quad9.net',
        'User-Agent': 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)',
        'Accept': '*/*',
        'Origin': 'https://quad9.net',
        'Referer': 'https://quad9.net/',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-GB,en-US;q=0.9,en;q=0.8',
        'Priority': 'u=1, i'
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Check for any request errors
        blocked_value = str(response.json().get("blocked"))

        if blocked_value == "True" or blocked_value == "true":
            malicious_domains.append(domain)
            print("Quad9:", domain, blocked_value)

    except UnicodeError:
        print(f"Quad9: UnicodeError, domain name too long, skipping check")
    except requests.exceptions.ConnectionError:
        print(f"Quad9: ConnectionError")
    except requests.exceptions.RequestException:
        print(f"Quad9: RequestException")
    except Exception as e:
        print(f"Quad9: Error: {e}")


def export_malicious_domains():
    if not malicious_domains:
        print("No malicious domains detected.")
    else:
        malicious_domains.sort()
        unique_domains = list(set(malicious_domains))
        unique_domains.sort()
        print("--------------------- \n", unique_domains)
        with open('result.txt', 'w') as result_file:
            for domain in unique_domains:
                result_file.write(domain + '\n')
        print(f"\n Matching phishing domains exported to 'result.txt'.")

    return malicious_domains


def main():
    display_art()
    try:
        if len(sys.argv) > 3 or len(sys.argv) < 1:
            raise ValueError("Invalid input. Usage: python PhishDetect.py <domains.txt> <virustotal.txt>")

        file_path = sys.argv[1]
        domains = read_from_file(file_path)
        domains.sort()
        if not domains:
            raise ValueError("No domains found in the file.")

        # Check all domains in GitHub Phishing.Database
        get_phishing_db(gh_phishing_feed, "GitHub PhishingDatabase", gh_phishing_db)
        check_phishing_db(file_path, "GitHub PhishingDatabase", gh_phishing_db)

        # Check all domains in OpenPhish feed
        get_phishing_db(open_phish_feed, "OpenPhish", open_phish_db)
        check_phishing_db(file_path, "OpenPhish", open_phish_db)

        # Check all domains in Discord Phishing list
        get_phishing_db(discord_phishing_feed, "Discord Phishing", discord_phishing_db)
        check_phishing_db(file_path, "Discord Phishing", discord_phishing_db)

        for domain in domains:
            if len(domain) > 4:  # validators.domain(domain): Basic domain length check
                check_quad9(domain)
                if is_valid_domain(domain):
                    check_virustotal(domain)
                else:
                    pass
                    # print(f"Skipping invalid domain: {domain} \n")

        export_malicious_domains()

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
