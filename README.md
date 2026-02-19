# RDP-MultiSession-Enabler
PowerShell script to enable multiple concurrent RDP sessions on Windows by patching termsrv.dll

# 🚀 RDP Multi-Session Enabler for Windows

[![Version](https://img.shields.io/badge/version-6.5-blue.svg)](https://github.com/malnwaihi/RDP-MultiSession-Enabler/releases)
[![PowerShell](https://img.shields.io/badge/powerShell-5.1%2B-brightgreen.svg)](https://github.com/PowerShell/PowerShell)
[![Windows](https://img.shields.io/badge/windows-11%2F10%2F7-blue.svg)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/v/release/malnwaihi/RDP-MultiSession-Enabler)](https://github.com/malnwaihi/RDP-MultiSession-Enabler/releases)


## 📋 Overview

**RDP Multi-Session Enabler** is a powerful PowerShell script that enables multiple concurrent Remote Desktop sessions on Windows client editions (Windows 11, 10, and 7). It patches the `termsrv.dll` file to bypass the single-user session limit, allowing multiple users to connect simultaneously to the same machine.

### ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🔄 **Multi-Session RDP** | Enable unlimited concurrent RDP sessions |
| 🖥️ **Universal Compatibility** | Works on Windows 11 (21H2-25H2), Windows 10, Windows 7 (64-bit) |
| 🔒 **Persistence Mode** | Survives reboots and Windows updates |
| 💾 **Automatic Backup** | Creates SHA256-verified backups before patching |
| ✅ **Byte-Level Validation** | Verifies patch integrity with checksums |
| 📋 **Session Monitoring** | View active RDP sessions in real-time |
| 🛡️ **Safety First** | System Restore Point integration and automatic rollback |
| 📝 **Full Logging** | Comprehensive activity logging for troubleshooting |

---

## 🚀 Quick Start

### Prerequisites
- ✅ Windows 7/10/11 (64-bit only)
- ✅ PowerShell 5.1 or higher
- ✅ Administrator privileges

### One-Line Installation

```powershell
```powershell
# Download and run (as Administrator)
iex (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/malnwaihi/RDP-MultiSession-Enabler/main/RDP-MultiSession-Enabler.ps1" -UseBasicParsing).Content
