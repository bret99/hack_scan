# hack_scan
Absolutely ultimate investigation framework showing how hackers see IP/IPs.

It's gonna be very useful for organizations that have few (or one) public IPs/IP. This framework includes the most used investigation providers such as Censys, CriminalIP, Shodan, Zoomeye and Nmap (with vulners API provided default command).

Finally one will see IPs/IP being investigated with hackers eyes.

One should enter IP or path to a text file with IPs list (one IP per line).

Prerequisites:
1. Censys secret key and api id
2. CriminalIP API key
3. Shodan API key
4. Zoomeye API key
5. Nmap preinstalled

One may change Nmap command in access_tokens.py. All API keys should also be located there.

One should keep in mind that some providers may block API requests for some reason. Especially it is actual for Zoomeye as well.

Command to run:
```
python3 hack_scan.py
```

---

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
