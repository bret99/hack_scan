import os
import requests
from access_tokens import censys_api_id, censys_secret_key
import sys
import time
import json

headers = {'Content-Type': 'application/json; charset=utf-8'}

def censys_hack():
    if censys_api_id == "" or censys_secret_key == "":
        sys.exit("\033[1;91m\nEmpty censys creds!\033[1;00m")
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
                json_object = requests.get("https://search.censys.io/api/v2/hosts/{}".format(IP.rstrip()), headers=headers, auth=(censys_api_id, censys_secret_key)).json()
                count = 0
                while count <= len(json_object["result"]["services"]):
                    try:    
                        print("\033[1;94mport\033[1;00m:\033[1;92m", json_object["result"]["services"][count]["port"], "\033[1;94mservice\033[1;00m:\033[1;92m", json_object["result"]["services"][count]["software"][0]["other"]["info"], "\033[1;94mtransport\033[1;00m:\033[1;92m", json_object["result"]["services"][count]["transport_protocol"], "\033[1;00m")
                        items_for_short_report.append("port: " + str(json_object["result"]["services"][count]["port"]) + " service: " + json_object["result"]["services"][count]["software"][0]["other"]["info"] + " transport: " + str(json_object["result"]["services"][count]["transport_protocol"]))
                    except KeyError:
                        try:
                            print("\033[1;94mport\033[1;00m:\033[1;92m", json_object["result"]["services"][count]["port"], "\033[1;94mservice\033[1;00m:\033[1;92m", json_object["result"]["services"][count]["software"][0]["product"], "\033[1;94mversion\033[1;00m:\033[1;92m" , json_object["result"]["services"][count]["software"][0]["version"], "\033[1;94mtransport\033[1;00m:\033[1;92m", json_object["result"]["services"][count]["transport_protocol"], "\033[1;00m")
                            items_for_short_report.append("port: " + str(json_object["result"]["services"][count]["port"]) + " service: " + json_object["result"]["services"][count]["software"][0]["product"] + " version: "  + json_object["result"]["services"][count]["software"][0]["version"] + " transport: " + str(json_object["result"]["services"][count]["transport_protocol"]))
                        except:
                            print("\033[1;94mport\033[1;00m:\033[1;92m", json_object["result"]["services"][count]["port"], "\033[1;94mservice\033[1;00m:\033[1;92m", json_object["result"]["services"][count]["service_name"], "\033[1;94mtransport\033[1;00m:\033[1;92m", json_object["result"]["services"][count]["transport_protocol"], "\033[1;00m")
                            items_for_short_report.append("port: " + str(json_object["result"]["services"][count]["port"]) + " service: " + json_object["result"]["services"][count]["service_name"] + " transport: " + str(json_object["result"]["services"][count]["transport_protocol"]))
                    except IndexError:
                        pass
                    count += 1
                print("\033[1;94mcountry\033[1;00m:\033[1;92m", json_object["result"]["location"]["country_code"], "\n\033[1;94mcity\033[1;00m:\033[1;92m", json_object["result"]["location"]["city"], "\n\033[1;94mlatitude\033[1;00m:\033[1;92m", json_object["result"]["location"]["coordinates"]["latitude"], "\n\033[1;94mlongitude\033[1;00m:\033[1;92m", json_object["result"]["location"]["coordinates"]["longitude"], "\n\033[1;94misp\033[1;00m:\033[1;92m", json_object["result"]["autonomous_system"]["name"], "\033[1;00m")
                items_for_short_report.append("country: " + json_object["result"]["location"]["country_code"] + "\ncity: " + json_object["result"]["location"]["city"] + "\nlatitude: " + str(json_object["result"]["location"]["coordinates"]["latitude"]) + "\nlongitude: " + str(json_object["result"]["location"]["coordinates"]["longitude"]) + "\nisp: " + json_object["result"]["autonomous_system"]["name"])
                try:
                    dns_counter = 0
                    if len(json_object["result"]["dns"]["names"]) == 0:
                        print("\033[1;94mdomains\033[1;00m: \033[;00m[]")
                        items_for_short_report.append("domains: []")
                    else:
                        print("\033[1;94mdomains\033[1;00m: ")
                        items_for_short_report.append("domains:")
                        for domain in json_object["result"]["dns"]["names"]:
                            print("\033[1;92m     {}\033[1;00m".format(json_object["result"]["dns"]["names"][dns_counter]))
                            items_for_short_report.append("     {}".format(json_object["result"]["dns"]["names"][dns_counter]))
                            dns_counter += 1
                except KeyError:
                    pass
            
                json_object_to_json_file = json.dumps(json_object, indent=4)
                if not os.path.exists("{}/reports".format(os.getcwd())):
                    os.mkdir("{}/reports".format(os.getcwd()))
                if not os.path.exists("{}/reports/censys".format(os.getcwd())):
                    os.mkdir("{}/reports/censys".format(os.getcwd()))
                
                with open("{0}/reports/censys/{1}_full_report.json".format(os.getcwd(), IP.rstrip()), "w") as outfile:
                    outfile.write(json_object_to_json_file)

                with open("{}/reports/censys/short_report.txt".format(os.getcwd()), "a") as outfile:
                    outfile.write("\n[" + IP.rstrip() + "] =>\n")
                    for line in items_for_short_report:
                        outfile.write(line + "\n")

            except KeyError:
                print("\033[1;93mNo information available for that IP\033[1;00m")
            print("\n==========================================================================================")
            time.sleep(1.0)

            if os.path.exists("{0}/reports/censys/{1}_full_report.json".format(os.getcwd(), IP.rstrip())):
                full_report_list.append(IP.rstrip())

    if os.path.exists("{}/reports/censys/short_report.txt".format(os.getcwd())):
        print("\nShort report located in \033[1;95m{}/reports/censys/short_report.txt\033[1;00m\n".format(os.getcwd()))
    if len(full_report_list) != 0:
        print("Full reports located in \033[1;95m{}/reports/censys/*_full_report.json\033[1;00m\n".format(os.getcwd()))


def IP_to_scan(IPs_input):
    if IPs_input == "":
        sys.exit("")
    try:
        print("\033[1;90m\nCollecting data...\033[1;00m\n")
        json_object = requests.get("https://search.censys.io/api/v2/hosts/{}".format(IPs_input), headers=headers, auth=(censys_api_id, censys_secret_key)).json()
        count = 0
        while count <= len(json_object["result"]["services"]):
            try:
                print("\033[1;94mport\033[1;00m:\033[1;92m", json_object["result"]["services"][count]["port"], "\033[1;94mservice\033[1;00m:\033[1;92m", json_object["result"]["services"][count]["software"][0]["other"]["info"], "\033[1;94mtransport\033[1;00m:\033[1;92m", json_object["result"]["services"][count]["transport_protocol"], "\033[1;00m")
            except KeyError:
                try:
                    print("\033[1;94mport\033[1;00m:\033[1;92m", json_object["result"]["services"][count]["port"], "\033[1;94mservice\033[1;00m:\033[1;92m", json_object["result"]["services"][count]["software"][0]["product"], json_object["result"]["services"][count]["software"][0]["version"], "\033[1;94mtransport\033[1;00m:\033[1;92m", json_object["result"]["services"][count]["transport_protocol"], "\033[1;00m")
                except:
                    print("\033[1;94mport\033[1;00m:\033[1;92m", json_object["result"]["services"][count]["port"], "\033[1;94mservice\033[1;00m:\033[1;92m", json_object["result"]["services"][count]["service_name"], "\033[1;94mtransport\033[1;00m:\033[1;92m", json_object["result"]["services"][count]["transport_protocol"], "\033[1;00m")
            except IndexError:
                pass
            count += 1
        print("\033[1;94mcountry\033[1;00m:\033[1;92m", json_object["result"]["location"]["country_code"], "\n\033[1;94mcity\033[1;00m:\033[1;92m", json_object["result"]["location"]["city"], "\n\033[1;94mlatitude\033[1;00m:\033[1;92m", json_object["result"]["location"]["coordinates"]["latitude"], "\n\033[1;94mlongitude\033[1;00m:\033[1;92m", json_object["result"]["location"]["coordinates"]["longitude"], "\n\033[1;94misp\033[1;00m:\033[1;92m", json_object["result"]["autonomous_system"]["name"], "\033[1;00m")
        
        json_object_to_json_file = json.dumps(json_object, indent=4)
        if not os.path.exists("{}/reports".format(os.getcwd())):
            os.mkdir("{}/reports".format(os.getcwd()))
        if not os.path.exists("{}/reports/censys".format(os.getcwd())):
            os.mkdir("{}/reports/censys".format(os.getcwd()))
        with open("{0}/reports/censys/{1}_full_report.json".format(os.getcwd(), IPs_input), "w") as outfile:
            outfile.write(json_object_to_json_file)
        
        print("\nOne can find full report in \033[1;95m{0}/reports/censys/{1}_full_report.json\033[1;00m\n".format(os.getcwd(), IPs_input))

    except KeyError:
        print("\033[1;93mNo information available for that IP\033[1;00m")
    except KeyboardInterrupt:
        sys.exit("\n")
