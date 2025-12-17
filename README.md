# MapR.py

MapR.py is a **Python-based Nmap wrapper** designed for **educational use and labs. While can be used in security assessments, I would recommend using the official nmap CLI tool or GUI.**  

It provides an interactive CLI interface for scanning **single hosts or CIDR ranges** while preserving core Nmap behavior and output structure.

> ⚠️ **Authorization Required**  
> You must own the target system or have **explicit permission** to scan it. Unauthorized scanning may be illegal.

---

## ✨ Features

- Interactive CLI menu
- Single IP scanning
- CIDR range scanning
- Skips hosts that are down (CIDR mode)
- Supports common Nmap scan flags
- Detects services and versions (`-sV`)
- Supports packet fragmentation (`-f`, `-ff`)
- Root privilege detection and warnings
- Clean, Nmap-style output formatting

---

## 📦 Requirements

- Python **3.8+**
- Nmap installed on the system
- Linux or macOS (raw scans require root)

### Python Dependencies

```bash
pip install python-nmap pyfiglet
```

---

## 🚀 Usage

Run the script:

```bash
sudo python3 MapR.py
```

> Running without `sudo` will limit certain scan types (`-sS`, `-f`, `-O`).

---

## 🧭 Menu Options

```
1. Scan single IP address
2. Scan a CIDR
3. Exit
```

---

## 🔍 Single Host Scan

You will be prompted for:
- Target IP address
- Timing template (`-T0` to `-T5`)
- Scan type (`-sS`, `-sU`, `-sX`, etc.)
- Fragmentation options (`-f`, `-ff`)
- General options (`-sV`, `-A`, `-O`)

### Example

```
Running: nmap -sS -sV -T4 10.10.10.10

Host: 10.10.10.10 (web01)
State: up
Protocol: tcp
Port: 22    State: open    Service: OpenSSH 8.2p1
Port: 80    State: open    Service: Apache httpd 2.4.41
```

---

## 🌐 CIDR Scanning

CIDR scans follow the **same output format** as single-host scans but:

- Only **hosts that are UP** are printed
- Each live host is listed separately

### Example

```
Running: nmap -sS -sV -T4 10.10.10.0/24

Host: 10.10.10.5 (web01)
State: up
Protocol: tcp
Port: 80    State: open    Service: Apache httpd 2.4.41

Host: 10.10.10.12 (db01)
State: up
Protocol: tcp
Port: 3306  State: open    Service: MySQL 8.0
```

---

## 🧪 Root Privilege Detection

MapR.py automatically checks for root privileges at startup.

If not run as root:

```
[!] Running without root: -sS, -f, -O may not work properly.
```

Raw packet scans and fragmentation **require root privileges**.

---

## 🧠 Supported Nmap Options

| Category | Examples |
|-------|---------|
| Scan Type | `-sS`, `-sU`, `-sX`, `-sI` |
| Timing | `-T0` – `-T5` |
| Fragmentation | `-f`, `-ff` |
| Detection | `-sV`, `-A`, `-O` |

> Note: Flags are passed directly to the system Nmap binary.

---

## 🔐 Legal & Ethical Use

This project is intended for:
- Learning
- Home labs
- CTFs
- Authorized penetration tests

**Do NOT use this tool to scan systems you do not own or have permission to test.**

The author assumes **no liability** for misuse.

## 🛠️ Future Improvements (Planned projects to add)

- Output export (JSON / CSV) 
- `--open` filtering
- Improved option validation ✅
- Colorized output 
- Script scan integration

---

## 👤 Author

**RippR**


---

## 📜 License

This project is released for **educational use**.  
Nmap is licensed separately under its own terms.

---

Happy scanning — responsibly 🚀

