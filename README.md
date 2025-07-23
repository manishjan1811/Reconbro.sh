# Reconbro.sh 🕵️‍♂️

**Reconbro.sh** is an advanced and user-friendly **web reconnaissance automation tool** designed to simplify and streamline the information gathering process during bug bounty or penetration testing.

---

## 🚀 Features

- ✅ Automated Subdomain Enumeration  
- ✅ Subdomain Filtering with Live Status Check  
- ✅ Visual Recon with Aquatone  
- ✅ Port Scanning using Naabu, Rustscan, and Nmap  
- ✅ Directory Fuzzing using Feroxbuster  
- ✅ Parameter Discovery from Wayback, GAU, Arjun, Hakrawler, etc.  
- ✅ JS File Analysis using SecretFinder  
- ✅ Auto Virtualenv Setup & Dependency Installation  
- ✅ Clean Output Structure & File Management

---

## 🛠️ Tools Used

- `subfinder`, `amass`, `findomain`, `assetfinder`  
- `httpx-toolkit`, `httprobe`  
- `aquatone`  
- `naabu`, `rustscan`, `nmap`  
- `feroxbuster`, `duplicut`  
- `waybackurls`, `getallurls`, `hakrawler`, `arjun`, `gauplus`  
- `SecretFinder`

---

## 📦 Prerequisites

Make sure all required tools are installed and available in your `$PATH`.  
Also ensure `python3`, `virtualenv`, and `pip` are installed.

To install dependencies for SecretFinder:
```bash
pip install requests jsbeautifier lxml requests-file
