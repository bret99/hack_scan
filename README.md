# hack_scan (Attack Surface Management Framework)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.8%20%7C%203.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)

`hack_scan` is a zero-dependency, high-efficiency security reconnaissance and Attack Surface Management (ASM) framework designed to analyze public IP infrastructures through an adversarial lens. By consolidating threat intelligence data from premier OSINT providers and validating perimeter exposure with active scanning, `hack_scan` delivers actionable visibility into what threat actors can discover about your external assets.

This tool is optimized for corporate security teams, network administrators, and compliance auditors managing a defined set of public-facing IP addresses.

## 🔍 Supported Intelligence Providers

The framework seamlessly aggregates data from top-tier cyber threat intelligence (CTI) platforms:
- **Censys API**: Deep internet-wide scanning data and certificate tracking.
- **CriminalIP API**: Real-time IP intelligence, threat scoring, and inbound/outbound risk profiling (10,000 free monthly requests).
- **Shodan API**: Device, banner, and protocol enumeration.
- **ZoomEye API**: Extensive cyberspace mapping and historical endpoint data.
- **Nmap + Vulners NSE**: Active port verification mapped against the Vulners CVE database for direct vulnerability identification.

## 🚀 Prerequisites

### System Dependencies
An active installation of `nmap` along with standard NSE scripts is required:
```bash
# Ubuntu / Debian
sudo apt-get update && sudo apt-get install -y nmap

# macOS
brew install nmap
```

## 🛠️ Installation & Configuration

1. **Clone the Repository:**
   ```bash
   git clone [https://github.com/bret99/hack_scan.git](https://github.com/bret99/hack_scan.git)
   cd hack_scan
   ```

2. **Configure Access Tokens:**
   Copy the template configuration file and populate it with your confidential API keys:
   ```bash
   cp access_tokens.py.template access_tokens.py
   ```
   Open `access_tokens.py` and supply your credentials:
   ```python
   censys_api_id = "your_censys_id"
   censys_secret_key = "your_censys_secret"
   criminalip_key = "your_criminalip_key" # 10000 requests per month for free members.
   shodan_key = "your_shodan_key"
   zoomeye_key = "your_zoomeye_key"

   # Customize the default Nmap command execution layout
   nmap_command = "nmap --script vulners -A"
   ```

## 💻 Usage

`hack_scan` provides an interactive entry point. It accepts either a single target IP address or a path to a plaintext file containing an IP list (one entry per line).

```bash
python3 hack_scan.py
```

> ⚠️ **Rate Limiting Notice:** Certain API providers (particularly ZoomEye) enforce strict rate limits or regional request blocks on free tier allocations. Ensure your subscription tier covers the volume of queried target hosts.

## 💎 Support the Project

If this tool helps protect your infrastructure, consider supporting the developer! 

### Crypto Wallets
| Asset | Network | Address |
| :--- | :--- | :--- |
| **BTC** | Bitcoin | `bc1qjwl80sv06xj2yhumn6k6xemchryem923wwts5x` |
| **USDT / ETH** | Ethereum (ERC20) | `0xc01b996c7b08ccfad463f27e54f1e74e6ac6f9ff` |
| **USDT / SOL** | Solana | `D7a5CdLaDwkKehnH82y6VJEF3hADWuupuhWCXecHvEnt` |
| **TON** | TON Network | `UQBhPLwdFiJdh6sZ96sZfxrxD9Lu6NFtaUecWeoHSM-EPc0P` |
| **LTC** | Litecoin | `ltc1qkm58ks5kuc64rjwd74sfalc5xsn7h6sr4vt45w` |
| **SOL** | Solana | `D7a5CdLaDwkKehnH82y6VJEF3hADWuupuhWCXecHvEnt` |

---

📜 License

This project is licensed under the MIT License - see the LICENSE file for details.
