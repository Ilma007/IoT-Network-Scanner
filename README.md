IoT Device Network Scanner —
===============================================

IMPORTANT (Legal/Ethical)
-------------------------
• Scan only networks/devices you own or have explicit permission to test.
• Unauthorized scanning can be illegal or against policy.

What this tool does
-------------------
• Discovers devices on your Wi‑Fi/LAN using ARP.
• Scans discovered devices for open ports using Nmap (top ports by default).
• Calculates a simple risk score based on open services (e.g., Telnet/FTP/SMB/RDP/UPnP/MQTT).
• Exports CSV and JSON reports you can share with parents/teachers/admins.

Prerequisites
-------------
1) Python 3.8+
2) Nmap installed (https://nmap.org/download.html) — add to PATH during install.
3) Packet capture driver:
   - Windows: Install Npcap (https://nmap.org/npcap/). Run terminal as Administrator.
   - Linux: libpcap is typically present; run with sudo.
   - macOS: libpcap included; run with sudo.

Setup
-----
# 1) Create a folder and copy these files inside it:
   iot_scanner.py
   requirements.txt

# 2) (Optional) Create virtual environment
   python -m venv .venv
   # Windows
   .venv\Scripts\activate
   # Linux/macOS
   source .venv/bin/activate

# 3) Install dependencies
   pip install -r requirements.txt

Run
---
• Quick scan (auto-detect network, top 50 ports)
   python iot_scanner.py

• Deep scan (service versions, top 200 ports)
   python iot_scanner.py --deep --top-ports 200

• Specify network manually
   python iot_scanner.py --cidr 192.168.1.0/24

• Choose interface (name varies by OS)
   python iot_scanner.py --iface "Wi-Fi"

Outputs
-------
• scan_report_YYYYMMDD_HHMMSS.csv
• scan_report_YYYYMMDD_HHMMSS.json
Columns include: IP, Hostname, MAC, Open Ports, Risk Label/Score, and reasons.

How it works (Short)
--------------------
1) ARP Scan: Broadcasts "who has IP X?" and records replies (IPs + MACs).
2) Port Scan: Uses Nmap via python-nmap to check common ports for each live host.
3) Risk Score: Assigns points if risky ports are open (e.g., Telnet/FTP/SMB/RDP/MQTT) and
   adds heuristics like "HTTP without HTTPS" or "many services exposed".
4) Report: Prints a table and saves CSV/JSON for review.

In deatails ---------------------
--IoT Device Network Scanner
📌 Overview

The IoT Device Network Scanner is a Python-based tool that scans devices connected to a Wi-Fi or hotspot network.
It helps detect:

Active devices (phones, laptops, smart TVs, IoT gadgets, etc.)

Their IP addresses and MAC addresses

Open ports and running services

Risk level (LOW / MEDIUM / HIGH)

This project is built to promote network awareness and safety among users — especially teens and beginners who want to understand who is connected to their network and whether it is safe.

❓ Why We Built This

Most people connect multiple devices to their Wi-Fi or hotspot, but don’t know what’s happening in the background.

Hackers often exploit open ports and weakly configured devices on local networks.

Parents, students, and beginners rarely check unauthorized devices using their network.

👉 This scanner makes it easy to see hidden risks and take action.

🎯 What It Does

Scans all devices on the same network

Shows IP address, Hostname, MAC address

Detects open ports and services

Assigns a risk score based on exposed services

Saves results in CSV and JSON reports for future use

Example output:

| IP             | Hostname | MAC Address       | Open Ports | Risk  | Score |
|----------------|----------|------------------|------------|-------|-------|
| 192.168.1.1    | Router   | 34:AB:CD:12:34:56 | 80,443     | MEDIUM| 45    |
| 192.168.1.105  | Phone    | 9C:XX:YY:ZZ:12:34 | 22         | HIGH  | 70    |

👥 Who Can Use This

Home users → check if unknown devices are connected to Wi-Fi.

Students → learn basics of networking and cybersecurity.

Parents → monitor hotspot/Wi-Fi usage in a safe way.

Beginners → explore port scanning and risk assessment.

🚀 How to Use

Install dependencies:

pip install psutil python-nmap tabulate scapy


(Windows users also need Npcap
.)

Run the scanner with your network range:

python iot_scanner.py --cidr 192.168.1.0/24 --scan


Reports will be saved in the same folder as:

scan_report_YYYYMMDD_HHMMSS.csv

scan_report_YYYYMMDD_HHMMSS.json

🖥️ Can We Make It a GUI?

Yes ✅
Currently, it runs in the terminal, but it can be easily converted into a GUI using:

Tkinter (Python built-in library for simple interfaces)

PyQt / PySide (for professional desktop apps)

Flask / Django (to make a web-based dashboard)

Future GUI idea:

A dashboard showing devices as cards

Risk levels shown with color coding (Green/Yellow/Red)

Export/Save buttons for reports

🌟 Unique Features / Future Scope

MAC Vendor Lookup → directly show device type (Samsung, Apple, Dell, etc.)

Real-time Alerts → notify if a new device joins the network

Graph View → visualize devices as network nodes

Auto-block feature → integrate with router APIs to block unknown devices

Cross-platform GUI → Windows, Linux, Android (via Kivy)

📂 Files in This Repo

iot_scanner.py → main scanner script

requirements.txt → required dependencies

README.md → project documentation

Example reports → sample .csv and .json files

📌 Conclusion

This project is not just a scanner — it’s a learning tool for cybersecurity and networking basics.
It helps people see what’s really happening on their Wi-Fi, identify risks, and take the first step towards safer internet usage.



proper guidance for run this project /////////////////////---------------------------------------///////////////////////////////////////////////
🖥️ How to Run IoT Network Scanner (Step by Step)
1️⃣ Clone or Download Project

If uploaded on GitHub:

git clone https://github.com/ilma007/IoT-Network-Scanner.git
cd IoT-Network-Scanner


(Else just go to your local project folder.)

2️⃣ Create & Activate Virtual Environment

Windows (PowerShell):

python -m venv .venv
.venv\Scripts\activate


Linux / Mac:

python3 -m venv .venv
source .venv/bin/activate

3️⃣ Install Dependencies
pip install -r requirements.txt


👉 If requirements.txt not available, install manually:

pip install python-nmap scapy tabulate psutil

4️⃣ Run the Scanner

Basic discovery (no port scan):

python iot_scanner.py --cidr 192.168.1.0/24


Discovery + Port scan (recommended):

python iot_scanner.py --cidr 192.168.1.0/24 --scan


Deep scan (service & version detection):

python iot_scanner.py --cidr 192.168.1.0/24 --scan --deep


Scapy ARP discovery (if you have Npcap + Admin rights on Windows):

python iot_scanner.py --cidr 192.168.1.0/24 --arp --iface "Wi-Fi" --scan

5️⃣ Output Reports

After scan, project saves 2 files in the same folder:

scan_report_YYYYMMDD_HHMMSS.csv

scan_report_YYYYMMDD_HHMMSS.json

6️⃣ Exit Virtual Environment

When done:

deactivate
