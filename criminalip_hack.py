import os
import requests
from access_tokens import criminalip_key
import sys
import time
import json

headers = {'x-api-key': criminalip_key}

def criminalip_hack():
    if criminalip_key == "":
        sys.exit("\033[1;91m\nEmpty criminalip key!\033[1;00m")
    try:
        IPs_input = input("Enter IP or path to file with IPs to be scanned: ")
        IPs_to_scan(IPs_input)
    except FileNotFoundError:
        IP_to_scan(IPs_input)
    except KeyboardInterrupt:
        sys.exit("\n")

def IPs_to_scan(IPs_input):
    full_report_list = []
    with open(IPs_input) as IPs_to_scan:
        print("\033[1;90m\nCollecting data...\033[1;00m")
        for IP in IPs_to_scan.readlines():
            items_for_short_report_set = set()
            items_for_short_report = []
            try:
                print("\n\033[1;95m{}\033[1;00m\n".format(IP.strip()))
                json_object = requests.get("https://api.criminalip.io/v1/ip/data?ip={}&full=true".format(IP.strip()), headers=headers).json()
                items_to_print = []
                count = 0
                while count <= len(json_object["port"]["data"]):
                    try:
                        items_to_print.append("\033[1;94mport\033[1;00m: \033[1;92m" + str(json_object["port"]["data"][count]["open_port_no"]) + " \033[1;94mservice\033[1;00m: \033[1;92m" + str(json_object["port"]["data"][count]["app_name"]) + " \033[1;94mversion\033[1;00m: \033[1;92m" + str(json_object["port"]["data"][count]["app_version"]) + " \033[1;94mtransport\033[1;00m: \033[1;92m" + str(json_object["port"]["data"][count]["socket"]) + "\033[1;00m")
                        items_for_short_report_set.add("port: " + str(json_object["port"]["data"][count]["open_port_no"]) + " service: " + str(json_object["port"]["data"][count]["app_name"]) + " version: " + str(json_object["port"]["data"][count]["app_version"]) + " transport: " + str(json_object["port"]["data"][count]["socket"]))
                    except IndexError:
                        pass
                    count += 1
                for item in set(items_to_print):
                    print(item)
                items_for_short_report = list(items_for_short_report_set)
                print("\033[1;94mcountry\033[1;00m:\033[1;92m", str(json_object["whois"]["data"][0]["org_country_code"]), "\n\033[1;94mcity\033[1;00m:\033[1;92m", str(json_object["whois"]["data"][0]["city"]), "\n\033[1;94mlatitude\033[1;00m:\033[1;92m", str(json_object["whois"]["data"][0]["latitude"]), "\n\033[1;94mlongitude\033[1;00m:\033[1;92m", str(json_object["whois"]["data"][0]["longitude"]), "\n\033[1;94misp\033[1;00m:\033[1;92m", str(json_object["whois"]["data"][0]["org_name"]), "\033[1;00m")
                items_for_short_report.append("country: " + str(json_object["whois"]["data"][0]["org_country_code"]) + "\ncity: " + str(json_object["whois"]["data"][0]["city"]) + "\nlatitude: " + str(json_object["whois"]["data"][0]["latitude"]) + "\nlongitude: " + str(json_object["whois"]["data"][0]["longitude"]) + "\nisp: " + str(json_object["whois"]["data"][0]["org_name"]))
                domains_counter = 0
                if len(json_object["domain"]["data"]) == 0:
                    print("\033[1;94mdomains\033[1;00m: \033[;00m[]")
                    items_for_short_report.append("domains: []")
                else:
                    print("\033[1;94mdomains\033[1;00m: ")
                    for domain in json_object["domain"]["data"]:
                        print("\033[1;92m     {}\033[1;00m".format(json_object["domain"]["data"][domains_counter]["domain"]))
                        items_for_short_report.append("     {}".format(json_object["domain"]["data"][domains_counter]["domain"]))
                        domains_counter += 1
                honeypots_counter = 0
                if len(json_object["honeypot"]["data"]) == 0:
                    print("\033[1;94mhoneypots\033[1;00m: \033[;00m[]")
                    items_for_short_report.append("honeypots: []")
                else:
                    print("\033[1;94mhoneypots\033[1;00m: ")
                    for honeypot in json_object["honeypot"]["data"]:
                        print("\033[1;92m     {}\033[1;00m".format(json_object["honeypot"]["data"][honeypots_counter]["dst_port"]))
                        items_for_short_report.append("     {}".format(json_object["honeypot"]["data"][honeypots_counter]["dst_port"]))
                        honeypots_counter += 1
                print("\033[1;94mtags\033[1;00m: ")
                items_for_short_report.append("tags: ")
                if str(json_object["tags"]["is_vpn"]) == "True":
                    print("\033[1;92m     vpn\033[1;00m")
                    items_for_short_report.append("     vpn")
                if str(json_object["tags"]["is_cloud"]) == "True":
                    print("\033[1;92m     cloud\033[1;00m")
                    items_for_short_report.append("     cloud")
                if str(json_object["tags"]["is_tor"]) == "True":
                    print("\033[1;92m     tor\033[1;00m")
                    items_for_short_report.append("     tor")
                if str(json_object["tags"]["is_proxy"]) == "True":
                    print("\033[1;92m     proxy\033[1;00m")
                    items_for_short_report.append("     proxy")
                if str(json_object["tags"]["is_hosting"]) == "True":
                    print("\033[1;92m     hosting\033[1;00m")
                    items_for_short_report.append("     hosting")
                if str(json_object["tags"]["is_mobile"]) == "True":
                    print("\033[1;92m     mobile\033[1;00m")
                    items_for_short_report.append("     mobile")
                if str(json_object["tags"]["is_darkweb"]) == "True":
                    print("\033[1;92m     darkweb\033[1;00m")
                    items_for_short_report.append("     darkweb")
                if str(json_object["tags"]["is_scanner"]) == "True":
                    print("\033[1;92m     scanner\033[1;00m")
                    items_for_short_report.append("     scanner")
                if str(json_object["tags"]["is_snort"]) == "True":
                    print("\033[1;92m     snort\033[1;00m")
                    items_for_short_report.append("     snort")
                vulns_counter = 0
                if len(json_object["vulnerability"]["data"]) == 0:
                    print("\033[1;94mvulns\033[1;00m: \033[;00m[]")
                    items_for_short_report.append("vulns: []")
                else:
                    print("\033[1;94mvulns\033[1;00m: ")
                    items_for_short_report.append("vulns: ")
                    for vuln in json_object["vulnerability"]["data"]:
                        print("\033[1;91m      {}\033[1;00m".format(json_object["vulnerability"]["data"][vulns_counter]["cve_id"]))
                        items_for_short_report.append("      {}".format(json_object["vulnerability"]["data"][vulns_counter]["cve_id"]))
                        vulns_counter += 1
            
                json_object_to_json_file = json.dumps(json_object, indent=4)
                if not os.path.exists("{}/reports".format(os.getcwd())):
                    os.mkdir("{}/reports".format(os.getcwd()))
                if not os.path.exists("{}/reports/criminalip".format(os.getcwd())):
                    os.mkdir("{}/reports/criminalip".format(os.getcwd()))
                
                with open("{0}/reports/criminalip/{1}_full_report.json".format(os.getcwd(), IP.strip()), "w") as outfile:
                    outfile.write(json_object_to_json_file)

                with open("{}/reports/criminalip/short_report.txt".format(os.getcwd()), "a") as outfile:
                    outfile.write("\n[" + IP.strip() + "] =>\n")
                    for line in items_for_short_report:
                        outfile.write(line + "\n")

            except KeyError:
                print("\033[1;93mNo information available for that IP\033[1;00m")
            print("\n==========================================================================================")
            time.sleep(1.0)
            
            if os.path.exists("{0}/reports/criminalip/{1}_full_report.json".format(os.getcwd(), IP.strip())):
                full_report_list.append(IP.strip())

    if os.path.exists("{}/reports/criminalip/short_report.txt".format(os.getcwd())):
        print("\nShort report located in \033[1;95m{}/reports/criminalip/short_report.txt\033[1;00m\n".format(os.getcwd()))
    if len(full_report_list) != 0:
        print("Full reports located in \033[1;95m{}/reports/criminalip/*_full_report.json\033[1;00m\n".format(os.getcwd()))

def IP_to_scan(IPs_input):
    if IPs_input == "":
        sys.exit("")
    try:
        print("\033[1;90m\nCollecting data...\033[1;00m\n")
        json_object = requests.get("https://api.criminalip.io/v1/ip/data?ip={}&full=true".format(IPs_input), headers=headers).json()
        items_to_print = []
        count = 0
        while count <= len(json_object["port"]["data"]):
            try:
                items_to_print.append("\033[1;94mport\033[1;00m: \033[1;92m" + str(json_object["port"]["data"][count]["open_port_no"]) + " \033[1;94mservice\033[1;00m: \033[1;92m" + json_object["port"]["data"][count]["app_name"] + " \033[1;94mversion\033[1;00m: \033[1;92m" + json_object["port"]["data"][count]["app_version"] + " \033[1;94mtransport\033[1;00m: \033[1;92m" + json_object["port"]["data"][count]["socket"] + "\033[1;00m")
            except IndexError:
                pass
            count += 1
        for item in set(items_to_print):
            print(item)
        print("\033[1;94mcountry\033[1;00m:\033[1;92m", json_object["whois"]["data"][0]["org_country_code"], "\n\033[1;94mcity\033[1;00m:\033[1;92m", json_object["whois"]["data"][0]["city"], "\n\033[1;94mlatitude\033[1;00m:\033[1;92m", json_object["whois"]["data"][0]["latitude"], "\n\033[1;94mlongitude\033[1;00m:\033[1;92m", json_object["whois"]["data"][0]["longitude"], "\n\033[1;94misp\033[1;00m:\033[1;92m", json_object["whois"]["data"][0]["org_name"], "\033[1;00m")
    
        domains_counter = 0
        if len(json_object["domain"]["data"]) == 0:
            print("\033[1;94mdomains\033[1;00m: \033[;00m[]")
        else:
            print("\033[1;94mdomains\033[1;00m: ")
            for domain in json_object["domain"]["data"]:
                print("\033[1;92m     {}\033[1;00m".format(json_object["domain"]["data"][domains_counter]["domain"]))
                domains_counter += 1
        honeypots_counter = 0
        if len(json_object["honeypot"]["data"]) == 0:
            print("\033[1;94mhoneypots\033[1;00m: \033[;00m[]")
        else:
            print("\033[1;94mhoneypots\033[1;00m: ")
            for honeypot in json_object["honeypot"]["data"]:
                print("\033[1;92m     {}\033[1;00m".format(json_object["honeypot"]["data"][honeypots_counter]["dst_port"]))
                honeypots_counter += 1
        print("\033[1;94mtags\033[1;00m: ")
        if str(json_object["tags"]["is_vpn"]) == "True":
            print("\033[1;92m     vpn\033[1;00m")
        if str(json_object["tags"]["is_cloud"]) == "True":
            print("\033[1;92m     cloud\033[1;00m")
        if str(json_object["tags"]["is_tor"]) == "True":
            print("\033[1;92m     tor\033[1;00m")
        if str(json_object["tags"]["is_proxy"]) == "True":
            print("\033[1;92m     proxy\033[1;00m")
        if str(json_object["tags"]["is_hosting"]) == "True":
            print("\033[1;92m     hosting\033[1;00m")
        if str(json_object["tags"]["is_mobile"]) == "True":
            print("\033[1;92m     mobile\033[1;00m")
        if str(json_object["tags"]["is_darkweb"]) == "True":
            print("\033[1;92m     darkweb\033[1;00m")
        if str(json_object["tags"]["is_scanner"]) == "True":
            print("\033[1;92m     scanner\033[1;00m")
        if str(json_object["tags"]["is_snort"]) == "True":
            print("\033[1;92m     snort\033[1;00m")
        vulns_counter = 0
        if len(json_object["vulnerability"]["data"]) == 0:
            print("\033[1;94mvulns\033[1;00m: \033[;00m[]")
        else:
            print("\033[1;94mvulns\033[1;00m: ")
            for vuln in json_object["vulnerability"]["data"]:
                print("\033[1;91m      {}\033[1;00m".format(json_object["vulnerability"]["data"][vulns_counter]["cve_id"]))
                vulns_counter += 1
        
        json_object_to_json_file = json.dumps(json_object, indent=4)
        if not os.path.exists("{}/reports".format(os.getcwd())):
            os.mkdir("{}/reports".format(os.getcwd()))
        if not os.path.exists("{}/reports/criminalip".format(os.getcwd())):
            os.mkdir("{}/reports/criminalip".format(os.getcwd()))
        with open("{0}/reports/criminalip/{1}_full_report.json".format(os.getcwd(), IPs_input), "w") as outfile:
            outfile.write(json_object_to_json_file)
        print("\nOne can find full report in \033[1;95m{0}/reports/criminalip/{1}_full_report.json\033[1;00m\n".format(os.getcwd(), IPs_input))

    except KeyError:
        print("\033[1;93mNo information available for that IP\033[1;00m")
    except KeyboardInterrupt:
        sys.exit("\n")
