SDEV220_Final_Project_Group1
🐾 Bloodhound

Bloodhound is a lightweight, GUI-based cybersecurity tool for ethical network reconnaissance. Built with Python and Tkinter, it features live packet sniffing, port scanning, and alert mechanisms for suspicious services — all wrapped in a hacker-style console interface.

🚀 Features

🎯 Target IP Selection: Easily set the IP address to scan.

📡 Port Scanner: Scans a user-defined port range and identifies open ports.

⚠️ Suspicious Port Alerts: Flags potentially dangerous services (e.g., RDP, Telnet, SMB).

📶 Packet Sniffer: Captures and logs live network packets using scapy.

📝 Packet Summary Logging: Automatically saves protocol stats to a .txt file.

💻 Hacker-Themed Interface: Choose between dark or light terminal-style themes.

🔊 Optional Sounds: Play alert or startup sounds to enhance feedback.

🧰 Tech Stack

Language: Python 3.x

Libraries:

tkinter – GUI framework

scapy – Packet sniffing

socket – Port scanning

threading – Parallel scanning/sniffing

playsound – Sound feedback

📂 File Structure

bash

Copy

Edit

Bloodhound/

├── BlooddhoundSDEV220Final.py       # Main app logic

├── bark.mp3                       # Alert sound (optional)

├── power_on_blip.mp3             # Startup sound (optional)

├── bloodhound_icon.png           # App icon (optional)

└── packet_summary.txt            # Generated log (after sniffing)

🛠️ Installation

Clone or download this repo.

Install dependencies:

bash

Copy

Edit

pip install scapy playsound

Run the application:

bash

Copy

Edit

python "BloodhounSDEV220Final.py"

⚠️ Note: Running packet sniffing requires admin/root privileges.

🧪 How to Use
Start App: Launch the Python script.

Set Target: Use “Enter Target IP” to define your scan destination.

Scan Ports: Run a scan across a specified range.

Sniff Packets: Start/stop packet capture to log live traffic.

View Results: See console-style logs and suspicious port alerts.

Save Summary: Export protocol stats after sniffing stops.

🔐 Ethical Disclaimer
This tool is intended for educational and ethical use only. Unauthorized scanning or sniffing of networks you do not own or have explicit permission to test may violate laws and policies.

👩‍💻 Author

Project Manager: Tyler Hall

GUI/ Front-End Dev: Nelson Marte

Packet Sniffing: Juvens & Doniana 

Port Scanning: Kezrae

Securrity & Documentation: Clayton and Kavon

