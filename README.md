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

Command to run: python3 hack_scan.py.
