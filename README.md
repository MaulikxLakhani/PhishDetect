# PhishDetect
A python script to detect phishing domains and malicious domains including domains containings malwares.

                                                                                                    
What is PhishDetect? 
-------------
PhishDetect is an opensource Intelligence (OSINT) security tool to identify phishing domains and malicious domains including domains containing malware.

**Data Sources:**
- Quad9 Blacklist
- Phishing Database
- OpenPhish
- Discord Phishing
- VirusTotal

**Key Features:**

*   Uses multiple credible data sources.
*   Integration with VirusTotal
*   Use different levels of threshold to fine tune.
*   Can be integrated with other threat intelligence tools and DNS sinkholes


How to Install
------------

```bash
    git clone https://github.com/MaulikxLakhani/Phish-Detect.git
    pip install -r requirements.txt
```
Make sure you have **Python** and **pip** in your environment.

How to Update
------------

To update your current version, just type the following commands:
```bash
    git clone https://github.com/MaulikxLakhani/PhishDetect.git
    cd PhishDetect
    pip install -r requirements.txt
```
The "pip install" is just to make sure no new libs were added with the new upgrade. 

Usage Examples
------------
Edit the "domains.txt" with your customised domain list to hunt. \
Add your API key(s) in the "virustotal.txt" file. (Optional) 

```bash
    # Lazy run with default options
    python PhishDetect.py <domains.txt> <virustotal.txt>
```

> [Required] domains.txt: A text file containing domain list with each domain in a separate line. \
> [Optional] virustotal.txt: A text file containing VirusTotal API keys with each key in a separate line.
    

Automations & Integrations
-------------
You can set up PhishDetect to run automatically using a task scheduler (such as crontab for Linux) to generate latest results.

Contributions
-------------
As an opensource project, everyone's welcome to contribute.
Do you have an integration idea or would like to share an integration you developed with our community? Open a GitHub issue or send me an email.

Feature Request
-------------
To request a new feature, create a "new issue" and describe the feature and potential use cases. You can upvote the "issue" and contribute to the discussions if something similar already exists.

Authors
-------------
Project Founder
*   Maulik Lakhani - [(LinkedIn)](https://in.linkedin.com/in/mauliklakhani)

Contributors
*   Please check the contributors page on GitHub

How to help
-------------
You can help this project in many ways:
*   Spread this project within your network.
*   Providing your time and coding skills to add more data sources into the project.
*   Build a decent but simple project webpage.
*   Provide access to OSINT feeds or phishing feeds.
*   Open new issues with new suggestions, ideas, bug report or feature requests.
*   Share your story how have you been using the PhishDetect and what impact it brought to you.
