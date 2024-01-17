# PhishDetect
A python tool to detect malicios and phishing domains.

What is PhishDetect?
-------------
PhishDetect is an opensource Intelligence (OSINT) security tool to identify malicious and phishing domains. 

**It does support some key features such as:**

*   Integration with VirusTotal
*   Use different levels of threshold to fine tune
*   Can be integrated with other threat intelligence tools and DNS sinkholes


How to Install
------------

```bash
    git clone https://github.com/MaulikxLakhani/Phish-Detect.git
    pip install -r requirements.txt
```
Make sure you have **Python 3.6+** and **pip3** in your environment



How to Update
------------
> :warning: **when updating**: especially for a major release, re-run the pip install to check for new dependencies.

To update your current version, just type the following commands inside the Phish-Detect directory:
```bash
    git pull
    pip install -r requirements.txt
```
The "pip install" is just to make sure no new libs were added with the new upgrade. 

Usage Examples
------------
Edit the "domains.txt" with your customised domain list to hunt.

```bash
    # Lazy run with default options
    python PhishDetect.py
```

Automations & Integrations
-------------
You can set up PhishDetect to run automatically using a task scheduler (such as crontab for Linux) to generate updated results daily.


As an opensource project, everyone's welcome to contribute.
Do you have an integration idea or would like to share an integration you developed with our community? Open a GitHub issue or send me an email.

Feature Request
-------------
To request a new feature, create a "new issue" and describe the feature and potential use cases. You can upvote the "issue" and contribute to the discussions if something similar already exists.

Authors
-------------
Project founder
*   Maulik Lakhani [(LinkedIn)](https://www.linkedin.com/in/andretenreiro/)

Contributors
*   Please check the contributors page on GitHub

How to help
-------------
You can help this project in many ways:
*   Spread this project within your network.
*   Providing your time and coding skills to enhance the project.
*   Build a decent but simple project webpage.
*   Provide access to OSINT feeds.
*   Open new issues with new suggestions, ideas, bug report or feature requests.
*   Share your story how have you been using the PhishDetect and what impact it brought to you.
