import os
import requests
from access_tokens import shodan_key
import sys
import time
import json

def shodan_hack():
    if shodan_key == "":
        sys.exit("\033[1;91m\nEmpty shodan key!\033[1;00m")
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
            items_for_short_report = []
            try:
                print("\n\033[1;95m{}\033[1;00m\n".format(IP.rstrip()))
                json_object = requests.get("https://api.shodan.io/shodan/host/{0}?key={1}".format(IP.rstrip(), shodan_key)).json()
                count = 0
                while count <= len(json_object["ports"]):
                    try:
                        print("\033[1;94mport\033[1;00m:\033[1;92m", json_object["data"][count]["port"], "\033[1;94mservice\033[1;00m:\033[1;92m", json_object["data"][count]["product"], "\033[1;94mversion\033[1;00m:\033[1;92m", json_object["data"][count]["version"], "\033[1;94mtransport\033[1;00m:\033[1;92m", json_object["data"][count]["transport"], "\033[1;00m")
                        items_for_short_report.append("port: " + str(json_object["data"][count]["port"]) + " service: " + json_object["data"][count]["product"] + " version: " + json_object["data"][count]["version"] + " transport: " + str(json_object["data"][count]["transport"]))
                    except KeyError:
                        try:
                            print("\033[1;94mport\033[1;00m:\033[1;92m", json_object["data"][count]["port"], "\033[1;94mservice\033[1;00m:\033[1;92m", json_object["data"][count]["product"], "\033[1;94mtransport\033[1;00m:\033[1;92m", json_object["data"][count]["transport"], "\033[1;00m")
                            items_for_short_report.append("port: " + str(json_object["data"][count]["port"]) + " service" + str(json_object["data"][count]["product"]) + " transport: " + str(json_object["data"][count]["transport"]))
                        except:
                            print("\033[1;94mport\033[1;00m:\033[1;92m", json_object["data"][count]["port"], "\033[1;94mtransport\033[1;00m:\033[1;92m", json_object["data"][count]["transport"], "\033[1;00m")
                            items_for_short_report.append("port: " + str(json_object["data"][count]["port"]) + " transport: " + str(json_object["data"][count]["transport"]))
                    except IndexError:
                        pass
                    count += 1
                print("\033[1;94mcountry\033[1;00m:\033[1;92m", json_object["country_code"], "\n\033[1;94mcity\033[1;00m:\033[1;92m", json_object["city"], "\n\033[1;94mlatitude\033[1;00m:\033[1;92m", json_object["latitude"], "\n\033[1;94mlongitude\033[1;00m:\033[1;92m", json_object["longitude"], "\n\033[1;94misp\033[1;00m:\033[1;92m", json_object["isp"], "\033[1;00m")
                items_for_short_report.append("country: " + json_object["country_code"] + "\ncity: " + json_object["city"] + "\nlatitude: " + str(json_object["latitude"]) + "\nlongitude: " + str(json_object["longitude"]) + "\nisp: " + json_object["isp"])
                try:
                    domains_counter = 0
                    if len(json_object["domains"]) == 0:
                        print("\033[1;94mdomains\033[1;00m: \033[;00m[]")
                        items_for_short_report.append("domains: []")
                    else:
                        print("\033[1;94mdomains\033[1;00m: ")
                        items_for_short_report.append("domains:")
                        for domain in json_object["domains"]:
                            print("\033[1;92m     {}\033[1;00m".format(json_object["domains"][domains_counter]))
                            items_for_short_report.append("     {}".format(json_object["domains"][domains_counter]))
                            domains_counter += 1
                    tags_counter = 0
                    if len(json_object["tags"]) == 0:
                        print("\033[1;94mtags\033[1;00m: \033[;00m[]")
                        items_for_short_report.append("tags: []")
                    else:
                        print("\033[1;94mtags\033[1;00m: ")
                        items_for_short_report.append("tags:")
                        for tag in json_object["tags"]:
                            print("\033[1;92m     {}\033[1;00m".format(json_object["tags"][tags_counter]))
                            items_for_short_report.append("     {}".format(json_object["tags"][tags_counter]))
                            tags_counter += 1
                    vulns_counter = 0
                    if len(json_object["vulns"]) == 0:
                        print("\033[1;94mvulns\033[1;00m: \033[;00m[]")
                        items_for_short_report.append("vulns: []")
                    else:
                        print("\033[1;94mvulns\033[1;00m: ")
                        items_for_short_report.append("vulns:")
                        for vuln in json_object["vulns"]:
                            print("\033[1;91m      {}\033[1;00m".format(json_object["vulns"][vulns_counter]))
                            items_for_short_report.append("      {}".format(json_object["vulns"][vulns_counter]))
                            vulns_counter += 1
                
                except KeyError:
                    pass
                
                json_object_to_json_file = json.dumps(json_object, indent=4)
                if not os.path.exists("{}/reports".format(os.getcwd())):
                    os.mkdir("{}/reports".format(os.getcwd()))
                if not os.path.exists("{}/reports/shodan".format(os.getcwd())):
                    os.mkdir("{}/reports/shodan".format(os.getcwd()))
                
                with open("{0}/reports/shodan/{1}_full_report.json".format(os.getcwd(), IP.rstrip()), "w") as outfile:
                    outfile.write(json_object_to_json_file)

                with open("{}/reports/shodan/short_report.txt".format(os.getcwd()), "a") as outfile:
                    outfile.write("\n[" + IP.rstrip() + "] =>\n")
                    for line in items_for_short_report:
                        outfile.write(line + "\n")
            
            except KeyError:
                print("\033[1;93mNo information available for that IP\033[1;00m")
            print("\n==========================================================================================")
            time.sleep(1.0)
            
            if os.path.exists("{0}/reports/shodan/{1}_full_report.json".format(os.getcwd(), IP.rstrip())):
                full_report_list.append(IP.rstrip())
    
    if os.path.exists("{}/reports/shodan/short_report.txt".format(os.getcwd())):
        print("\nShort report located in \033[1;95m{}/reports/shodan/short_report.txt\033[1;00m\n".format(os.getcwd()))
    if len(full_report_list) != 0:
        print("Full reports located in \033[1;95m{}/reports/shodan/*_full_report.json\033[1;00m\n".format(os.getcwd()))

def IP_to_scan(IPs_input):
    if IPs_input == "":
        sys.exit("")
    try:
        print("\033[1;90m\nCollecting data...\033[1;00m\n")
        json_object = requests.get("https://api.shodan.io/shodan/host/{0}?key={1}".format(IPs_input, shodan_key)).json()
        count = 0
        while count <= len(json_object["ports"]):
            try:
                print("\033[1;94mport\033[1;00m:\033[1;92m", json_object["data"][count]["port"], "\033[1;94mservice\033[1;00m:\033[1;92m", json_object["data"][count]["product"], "\033[1;94mversion\033[1;00m:\033[1;92m", json_object["data"][count]["version"], "\033[1;94mtransport\033[1;00m:\033[1;92m", json_object["data"][count]["transport"], "\033[1;00m")
            except KeyError:
                try:
                    print("\033[1;94mport\033[1;00m:\033[1;92m", json_object["data"][count]["port"], "\033[1;94mservice\033[1;00m:\033[1;92m", json_object["data"][count]["product"], "\033[1;94mtransport\033[1;00m:\033[1;92m", json_object["data"][count]["transport"], "\033[1;00m")
                except:
                    print("\033[1;94mport\033[1;00m:\033[1;92m", json_object["data"][count]["port"], "\033[1;94mtransport\033[1;00m:\033[1;92m", json_object["data"][count]["transport"], "\033[1;00m")
            except IndexError:
                pass
            count += 1
        print("\033[1;94mcountry\033[1;00m:\033[1;92m", json_object["country_code"], "\n\033[1;94mcity\033[1;00m:\033[1;92m", json_object["city"], "\n\033[1;94mlatitude\033[1;00m:\033[1;92m", json_object["latitude"], "\n\033[1;94mlongitude\033[1;00m:\033[1;92m", json_object["longitude"], "\n\033[1;94misp\033[1;00m:\033[1;92m", json_object["isp"], "\033[1;00m")
        try:
            domains_counter = 0
            if len(json_object["domains"]) == 0:
                print("\033[1;94mdomains\033[1;00m: \033[;00m[]")
            else:
                print("\033[1;94mdomains\033[1;00m: ")
                for domain in json_object["domains"]:
                    print("\033[1;92m     {}\033[1;00m".format(json_object["domains"][domains_counter]))
                    domains_counter += 1
            tags_counter = 0
            if len(json_object["tags"]) == 0:
                print("\033[1;94mtags\033[1;00m: \033[;00m[]")
            else:
                print("\033[1;94mtags\033[1;00m: ")
                for tag in json_object["tags"]:
                    print("\033[1;92m     {}\033[1;00m".format(json_object["tags"][tags_counter]))
                    tags_counter += 1
            vulns_counter = 0
            if len(json_object["vulns"]) == 0:
                print("\033[1;94mvulns\033[1;00m: \033[;00m[]")
            else:
                print("\033[1;94mvulns\033[1;00m: ")
                for vuln in json_object["vulns"]:
                    print("\033[1;91m      {}\033[1;00m".format(json_object["vulns"][vulns_counter]))
                    vulns_counter += 1
        
        except KeyError:
            pass
        
        json_object_to_json_file = json.dumps(json_object, indent=4)
        if not os.path.exists("{}/reports".format(os.getcwd())):
            os.mkdir("{}/reports".format(os.getcwd()))
        if not os.path.exists("{}/reports/shodan".format(os.getcwd())):
            os.mkdir("{}/reports/shodan".format(os.getcwd()))
        with open("{0}/reports/shodan/{1}_full_report.json".format(os.getcwd(), IPs_input), "w") as outfile:
            outfile.write(json_object_to_json_file)

        print("\nOne can find full report in \033[1;95m{0}/reports/shodan/{1}_full_report.json\033[1;00m\n".format(os.getcwd(), IPs_input))

    except KeyError:
        print("\033[1;93mNo information available for that IP\033[1;00m")
    except KeyboardInterrupt:
        sys.exit("\n")
