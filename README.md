# 🔍 Network Packet Sniffer (Cyber Security Project)

A **professional-grade Network Packet Sniffer** built using Python and **Scapy**, enhanced with real-time visualizations using **Colorama**.  
Designed for **cybersecurity students, SOC analysts, and network engineers** to monitor live network traffic with protocol filtering and statistical insights.

---

## 🚀 Features

- 🖥️ Interface selection (`eth0`, `wlan0`, etc.)
- 🛂 Protocol filtering (`TCP`, `UDP`, `HTTP`)
- 🎯 Full **BPF (Berkeley Packet Filter) support**
- 📡 Live terminal output with **color-coded packet summaries**
- 📊 Real-time statistics including:
  - Total packets
  - Packets per second
  - Protocol usage breakdown
- 💾 Option to save packets as **PCAP file**
- 🛑 Graceful exit using **Ctrl + C**
- 🌐 Displays HTTP Host + Path when available

---

## 📦 Installation

```bash
pip install scapy colorama

Ensure the script is executed with administrator/root privileges:

sudo python sniffer.py


---

▶️ Usage Examples

1️⃣ Capture all traffic

sudo python sniffer.py

2️⃣ Capture only TCP packets on eth0

sudo python sniffer.py -i eth0 -p tcp

3️⃣ Use BPF filter to capture HTTP (port 80)

sudo python sniffer.py -b "tcp port 80"

4️⃣ Capture 100 packets and save to file

sudo python sniffer.py -c 100 -o capture.pcap

5️⃣ Capture HTTPS traffic with BPF

sudo python sniffer.py -b "tcp port 443" -o https_traffic.pcap


---

📂 Project Structure

📁 Project Root
│── sniffer.py       # Main script
│── README.md        # Documentation


---

📊 Example Capture Output

📊 CAPTURE STATISTICS
⏱️ Duration: 12.45 seconds
📦 Total Packets: 284
💾 Packets Per Second: 22.82

Protocol Breakdown:
🌐 HTTP           ████████  95 (33.5%)
📡 TCP            ██████    75 (26.4%)
🏓 ICMP (Ping)    ██        35 (12.3%)
📤 UDP            ██        30 (10.5%)
🔒 HTTPS          ██        20 (7.0%)
❓ OTHER          █         29 (10.2%)

If packets are saved:

💾 Packets saved to: capture.pcap

(Open with Wireshark or similar tool)


---

⚠️ Disclaimer (Very Important)

> This tool is for educational and authorized security testing purposes only.
Capturing packets on networks without permission is illegal.



✔ Use responsibly
✔ Obtain proper authorization
❌ Developer is not responsible for misuse


---

🔮 Future Enhancements

GUI dashboard for live monitoring

Suspicious packet alerts

Export statistics to JSON/CSV

TLS/SSL detection

Machine learning-based anomaly detection


---

🎯 Conclusion

This project provides a hands-on approach to network analysis and cybersecurity monitoring.
Ideal for learning, penetration testing labs, and SOC training environments.

> 🚀 Happy Packet Sniffing!




---

---

If you'd like:
- 📄 A polished **GitHub description**
- 🎓 A **project report** (for college submission)
- 🧪 Instructions to test it in **Kali Linux**
- 📘 A **PowerPoint or PDF documentation**
