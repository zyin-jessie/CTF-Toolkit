```
 ███  █████ █████    █████  ███   ███  █     █   █ ███ █████
█       █   █          █   █   █ █   █ █     █  █   █    █
█       █   ████       █   █   █ █   █ █     ███    █    █
█       █   █          █   █   █ █   █ █     █  █   █    █
 ███    █   █          █    ███   ███  █████ █   █ ███   █   
```

<div align="center">
    <img src="https://img.shields.io/badge/Python-3.14.0-%233776AB?style=for-the-badge&logo=python&logoColor=FFFFFF" alt="python"/>
    <img src="https://img.shields.io/badge/linux-%23000000?style=for-the-badge&logo=linux&logoColor=FFFFFF" alt="Linux"/>
    <img src="https://img.shields.io/badge/PowerShell-Badge?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAzMiAzMiI+PHBhdGggZD0iTTggMjJsOC02LTgtNk0xOCAyMmg2IiBzdHJva2U9IiNmZmYiIHN0cm9rZS13aWR0aD0iMi4yIiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiIGZpbGw9Im5vbmUiLz48L3N2Zz4=&logoSize=auto&23ED8B00&color=%23012456&cacheSeconds=86400)](https://learn.microsoft.com/powershell" alt="PowerShell"/>
</div>

# CTF-Toolkit

**CTF-Toolkit** is a lightweight command-line toolkit designed for **CTF enthusiasts** and security researchers. It helps you quickly **decode classical ciphers**, **crack hashes**, and automate common crypto and reversing tasks.

## Current Features

- Cross-platform (Linux, macOS, Windows) Python-based CLI toolkit.
- Hash cracking with dictionary attacks supporting 50+ hash types:
  Raw (MD4, MD5, SHA-1/224/256/384/512, SHA3, Keccak, Blake2),
  Crypt-based (descrypt, md5crypt, sha256crypt, sha512crypt, SunMD5),
  HMAC / PBKDF2 variants, Windows (NTLM, NetNTLMv2, MSCHAPv2),
  Database (MySQL, MSSQL, PostgreSQL, Oracle), Django, PHPS2, and more.
- Vigenere cipher decoding.
- Encoding / Decoding tools: Base64, Base32, Hex, URL, Binary,
  ROT13, ROT47, Caesar, Atbash, Reverse, ASCII converter.
- XOR cipher with key-based encryption and single-byte brute-force.
- Arrow-key navigated TUI menu with green selection indicator.
- Modular class-based architecture for easy extension.

## Upcoming Features

- More classical ciphers (Affine, Beaufort, etc.).
- Frequency analysis and pattern detection.
- Workspace mode for saving outputs.
- Modular plugin system for community extensions.

## Installation Guide

### Prerequisites
Ensure you have the following installed on your system:
- **Git** version 2.45.1 or higher
- **Python** version 3.14.0 or higher

## Linux / macOS

**Step 1: Open Terminal**

**Step 2: Clone the Repository**
```bash
git clone https://github.com/zyin-jessie/PwnStar-Toolkit.git
cd PwnStar-Toolkit
```

**Step 3: Make the Launcher Executable**
```bash
chmod +x pwnstar
```

**Step 4: Add to PATH (optional — lets you run `pwnstar` from anywhere)**
```bash
echo 'export PATH="$PATH:'"$(pwd)"'"' >> ~/.bashrc
source ~/.bashrc
```

**Step 5: Launch the Toolkit**
```bash
./pwnstar
```
Or from anywhere after adding to PATH:
```bash
pwnstar
```

## Windows

**Step 1: Open Command Prompt**
- Press `Windows + R`, type `cmd`, and press Enter
- Or search for "Command Prompt" in the Start menu

**Step 2: Navigate to Root Drive**
```cmd
cd C:\
```

**Step 3: Clone the Repository**
```cmd
git clone https://github.com/zyin-jessie/PwnStar-Toolkit.git
```

**Step 4: Add to System PATH**
- Search for "Environment Variable" in the Start menu
- Click "Edit the system environment variables"
- Click "Environment Variables" button
- Under "User variables", select "Path" and click "Edit"
- Click "New" and add the following path:
```cmd
C:\PwnStar-Toolkit
```

**Step 5: Launch the Toolkit**
- Open a new Command Prompt window
- Type the following command:
```cmd
pwnstar
```
