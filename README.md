# Deep Packet Inspection (DPI) & Intrusion Prevention System (IPS)

An advanced, real-time desktop network security dashboard built in Java. This application captures live socket traffic, decodes network protocols (Ethernet, IPv4, TCP, UDP, DNS, HTTP, HTTPS), translates dynamic IPs using passive DNS mapping, and executes deep payload scanning against regex threat signatures to intercept exploits and enforce firewall rules.

## 🚀 Key Features

* **Live Asynchronous Capturing**: Dynamically queries network interface cards (NICs) and captures socket frames using Pcap4J and Native Java Access (JNA).
* **Passive DNS Mapping & IP Caching**: Solves domain-blocking bypasses caused by browser DNS caching and connection reuse. It parses UDP DNS response payloads (port 53 Type A records) to dynamically map domains to target IPs.
* **Intrusion Prevention Engine**: Performs deep payload inspection using regular expressions to block common web application exploits (SQL Injection, Cross-Site Scripting, Path Traversal, and Command Injection/RCE).
* **Dynamic IP Blacklisting**: Automatically blacklists source IP addresses that trigger threat signatures, dropping all subsequent packets from that origin.
* **Sleek Cybersecurity Dashboard**: Styled with a dark theme (FlatLaf) featuring:
  * Real-time packet throughput (PPS) and threat (TPS) telemetry charts.
  * Flashing red security alert drawer.
  * Monospace Hex-Dump inspector showing raw payload byte grids.
  * Searchable historical logs with CSV export.

---

## 🛠️ Technology Stack & Dependencies

* **Language**: Java SE 17+ (Java 24 verified)
* **GUI Engine**: Java Swing with FlatLaf (Flat Dark Look & Feel)
* **Capturing Engine**: Pcap4J 1.8.2 & JNA 5.13.0
* **Persistence Layer**: SQLite JDBC 3.45.2.0 (using WAL mode for concurrent writes)
* **System Redirection**: Hosts-file loopback routing (`C:\Windows\System32\drivers\etc\hosts`)

---

## ⚙️ Setup & Installation

### Prerequisites (Windows)
1. **Java JDK**: Install JDK 17 or higher.
2. **Npcap Driver**: Install [Npcap](https://npcap.com/) (select "Install Npcap in WinPcap API-compatible mode" during installation) to enable socket-level sniffing.

### Build and Run Instructions

1. **Clone the Repository**:
   ```cmd
   git clone <your-repository-url>
   cd deep-packet-inspection-ips
   ```

2. **Download Dependencies**:
   Right-click `setup_libs.ps1` and select **Run with PowerShell** to download the required JAR files (`flatlaf`, `sqlite-jdbc`, `pcap4j`, `jna`, `slf4j`) into the `lib/` directory.

3. **Compile and Run**:
   Run the project using the batch file. **Note: Must be run as Administrator** to bind to physical NICs and sync hosts file rules:
   ```cmd
   compile_and_run.bat
   ```

---

## 📂 Project Architecture

```
com.cyber.dpi
├── App.java                   # Main bootstrapper and database init
├── analyzer
│   ├── AnalyzerTest.java      # Suite of 7 automated unit and logic tests
│   ├── PayloadInspector.java  # Regex payload matching engine
│   └── ProtocolAnalyzer.java  # Decodes DNS, TLS SNI, HTTP, and Hex Dumps
├── capture
│   ├── PacketCaptureEngine.java # Intercepts live socket frames via Pcap4J
│   └── PacketSimulator.java   # Offline traffic generator fallback
├── db
│   ├── DatabaseManager.java   # SQLite operations and IP-Domain translation maps
│   └── HostsFileSynchronizer.java # Syncs website block rules to the OS hosts file
├── detector
│   └── ThreatDetectionEngine.java # Intrusion rules and dynamic blacklisting
└── model
    ├── PacketLog.java         # Data model representing individual packet logs
    └── ThreatSignature.java   # Data model for inspection signatures
```

---

## 🛡️ License

This project is licensed under the MIT License - see the LICENSE file for details.
