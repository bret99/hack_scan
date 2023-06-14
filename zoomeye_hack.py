import os
import requests
from access_tokens import zoomeye_key
import sys
import time
import json

headers = {'API-KEY': zoomeye_key}

def zoomeye_hack():
    if zoomeye_key == "":
        sys.exit("\033[1;91m\nEmpty zoomeye key!\033[1;00m")
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
                print("\n\033[1;95m{}\033[1;00m\n".format(IP.strip()))
                json_object = requests.get("https://api.zoomeye.org/host/search?query=ip:{}".format(IP.strip()), headers=headers).json()
                count = 0
                while count < len(json_object["matches"]):
                    try:
                        print("\033[1;94mport\033[1;00m:\033[1;92m", json_object["matches"][count]["portinfo"]["port"], "\033[1;94mservice\033[1;00m:\033[1;92m", json_object["matches"][count]["portinfo"]["extrainfo"], "\033[1;94mtransport\033[1;00m:\033[1;92m", json_object["matches"][count]["protocol"]["transport"], "\033[1;94mhoneypot\033[1;00m:\033[1;92m", json_object["matches"][count]["honeypot"], "\033[1;00m")
                        items_for_short_report.append("port: " + str(json_object["matches"][count]["portinfo"]["port"]) + " service: " + json_object["matches"][count]["portinfo"]["extrainfo"] + " transport: " + str(json_object["matches"][count]["protocol"]["transport"] + " honeypot: " + str(json_object["matches"][count]["honeypot"])))
                    except KeyError:
                        print("\033[1;94mport\033[1;00m:\033[1;92m", str(json_object["matches"][count]["portinfo"]["port"]), "\033[1;94mservice\033[1;00m:\033[1;92m", str(json_object["matches"][count]["portinfo"]["app"]), "\033[1;94mversion\033[1;00m:\033[1;92m", str(json_object["matches"][count]["portinfo"]["version"]), "\033[1;94mtransport\033[1;00m:\033[1;92m", str(json_object["matches"][count]["protocol"]["transport"]), "\033[1;94mhoneypot\033[1;00m:\033[1;92m", str(json_object["matches"][count]["honeypot"]), "\033[1;00m")
                        items_for_short_report.append("port: " + str(json_object["matches"][count]["portinfo"]["port"]) + " service: " + str(json_object["matches"][count]["portinfo"]["app"]) + " version: " + str(json_object["matches"][count]["portinfo"]["version"]) + " transport: " + str(json_object["matches"][count]["protocol"]["transport"]) + " honeypot: " + str(json_object["matches"][count]["honeypot"]))
                    count += 1
                try:
                    print("\033[1;94mcountry\033[1;00m:\033[1;92m", str(json_object["matches"][0]["geoinfo"]["country"]["code"]), "\n\033[1;94mcity\033[1;00m:\033[1;92m", str(json_object["matches"][0]["geoinfo"]["city"]["names"]["en"]), "\n\033[1;94mlatitude\033[1;00m:\033[1;92m", str(json_object["matches"][0]["geoinfo"]["location"]["lat"]), "\n\033[1;94mlongitude\033[1;00m:\033[1;92m", str(json_object["matches"][0]["geoinfo"]["location"]["lon"]), "\n\033[1;94misp\033[1;00m:\033[1;92m", str(json_object["matches"][0]["geoinfo"]["isp"]), "\033[1;00m")
                    items_for_short_report.append("country: " + str(json_object["matches"][0]["geoinfo"]["country"]["code"]) + "\ncity: " + str(json_object["matches"][0]["geoinfo"]["city"]["names"]["en"]) + "\nlatitude: " + str(json_object["matches"][0]["geoinfo"]["location"]["lat"]) + "\nlongitude: " + str(json_object["matches"][0]["geoinfo"]["location"]["lon"]) + "\nisp: " + str(json_object["matches"][0]["geoinfo"]["isp"]))
                except IndexError:
                    pass
                except TypeError:
                    pass

                json_object_to_json_file = json.dumps(json_object, indent=4)
                if not os.path.exists("{}/reports".format(os.getcwd())):
                    os.mkdir("{}/reports".format(os.getcwd()))
                if not os.path.exists("{}/reports/zoomeye".format(os.getcwd())):
                    os.mkdir("{}/reports/zoomeye".format(os.getcwd()))
                
                with open("{0}/reports/zoomeye/{1}_full_report.json".format(os.getcwd(), IP.strip()), "w") as outfile:
                    outfile.write(json_object_to_json_file)

                with open("{}/reports/zoomeye/short_report.txt".format(os.getcwd()), "a") as outfile:
                    outfile.write("\n[" + IP.strip() + "] =>\n")
                    for line in items_for_short_report:
                        outfile.write(line + "\n")

            except KeyError:
                print("\033[1;93mNo information available for that IP\033[1;00m")
            print("\n==========================================================================================")
            time.sleep(2.0)
            
            if os.path.exists("{0}/reports/zoomeye/{1}_full_report.json".format(os.getcwd(), IP.strip())):
                full_report_list.append(IP.strip())

    if os.path.exists("{}/reports/zoomeye/short_report.txt".format(os.getcwd())):
        print("\nShort report located in \033[1;95m{}/reports/zoomeye/short_report.txt\033[1;00m\n".format(os.getcwd()))
    if len(full_report_list) != 0:
        print("Full reports located in \033[1;95m{}/reports/zoomeye/*_full_report.json\033[1;00m\n".format(os.getcwd()))

def IP_to_scan(IPs_input):
    if IPs_input == "":
        sys.exit("")
    try:
        print("\033[1;90m\nCollecting data...\033[1;00m\n")
        json_object = requests.get("https://api.zoomeye.org/host/search?query=ip:{}".format(IPs_input), headers=headers).json()
        count = 0
        while count < len(json_object["matches"]):
            try:
                print("\033[1;94mport\033[1;00m:\033[1;92m", str(json_object["matches"][count]["portinfo"]["port"]), "\033[1;94mservice\033[1;00m:\033[1;92m", str(json_object["matches"][count]["portinfo"]["extrainfo"]), "\033[1;94mtransport\033[1;00m:\033[1;92m", str(json_object["matches"][count]["protocol"]["transport"]), "\033[1;94mhoneypot\033[1;00m:\033[1;92m", str(json_object["matches"][count]["honeypot"]), "\033[1;00m")
            except KeyError:
                print("\033[1;94mport\033[1;00m:\033[1;92m", str(json_object["matches"][count]["portinfo"]["port"]), "\033[1;94mservice\033[1;00m:\033[1;92m", str(json_object["matches"][count]["portinfo"]["app"]), "\033[1;94mversion\033[1;00m:\033[1;92m", str(json_object["matches"][count]["portinfo"]["version"]), "\033[1;94mtransport\033[1;00m:\033[1;92m", str(json_object["matches"][count]["protocol"]["transport"]), "\033[1;94mhoneypot\033[1;00m:\033[1;92m", str(json_object["matches"][count]["honeypot"]), "\033[1;00m")
            count += 1
        try:
            print("\033[1;94mcountry\033[1;00m:\033[1;92m", str(json_object["matches"][0]["geoinfo"]["country"]["code"]), "\n\033[1;94mcity\033[1;00m:\033[1;92m", str(json_object["matches"][0]["geoinfo"]["city"]["names"]["en"]), "\n\033[1;94mlatitude\033[1;00m:\033[1;92m", str(json_object["matches"][0]["geoinfo"]["location"]["lat"]), "\n\033[1;94mlongitude\033[1;00m:\033[1;92m", str(json_object["matches"][0]["geoinfo"]["location"]["lon"]), "\n\033[1;94misp\033[1;00m:\033[1;92m", str(json_object["matches"][0]["geoinfo"]["isp"]), "\033[1;00m")
        except TypeError:
            pass
        except IndexError:
            print("\033[1;93mNo information available for that IP\033[1;00m")

        json_object_to_json_file = json.dumps(json_object, indent=4)
        if not os.path.exists("{}/reports".format(os.getcwd())):
            os.mkdir("{}/reports".format(os.getcwd()))
        if not os.path.exists("{}/reports/zoomeye".format(os.getcwd())):
            os.mkdir("{}/reports/zoomeye".format(os.getcwd()))
        with open("{0}/reports/zoomeye/{1}_full_report.json".format(os.getcwd(), IPs_input), "w") as outfile:
            outfile.write(json_object_to_json_file)
        
        print("\nOne can find full report in \033[1;95m{0}/reports/zoomeye/{1}_full_report.json\033[1;00m\n".format(os.getcwd(), IPs_input))

    except KeyError:
        print("\033[1;93mNo information available for that IP\033[1;00m")
    except KeyboardInterrupt:
        sys.exit("\n")
