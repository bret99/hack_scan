import os
import multiprocessing
from access_tokens import nmap_command
import sys

def nmap_hack():
    if nmap_command == "":
        sys.exit("\033[1;91m\nEmpty Nmap command!\033[1;00m")
    try:
        threads_list = []
        IPs_input = input("Enter IP or path to file with IPs to be scanned: ").strip()
        with open(IPs_input) as IPs_to_scan:
            for IP in IPs_to_scan.readlines():
                print("\n\033[1;95m{}\033[1;00m".format(IP.strip()))
                thread = multiprocessing.Process(target=IP_to_scan(IP.strip()))
                threads_list.append(thread)
                thread.start()
                print("\n==========================================================================================")
        for threads in threads_list:
            threads.join()
    
#        if not os.path.exists("{}/reports".format(os.getcwd())):
#            os.mkdir("{}/reports".format(os.getcwd()))
#        if not os.path.exists("{}/reports/nmap".format(os.getcwd())):
#            os.mkdir("{}/reports/nmap".format(os.getcwd()))

    except FileNotFoundError:
        IP_to_scan(IPs_input)
    except KeyboardInterrupt:
        sys.exit("\n")

    os.chdir("{}/reports/nmap".format(os.getcwd()))
    for item in os.listdir("."):
        try:
            with open(item) as file_out:
                if len(file_out.readlines()) <= 4:
                    os.remove(item)
        except (UnicodeDecodeError, IsADirectoryError):
            pass

    if len(os.listdir("{}".format(os.getcwd()))) != 0:
        print("\nOne can find reports in \033[1;95m{}/*_nmap_report.txt\033[1;00m\n".format(os.getcwd()))


def IP_to_scan(IPs_input):
    try:
        if IPs_input == "":
            sys.exit("")
        print("")
        if not os.path.exists("{}/reports".format(os.getcwd())):
            os.mkdir("{}/reports".format(os.getcwd()))
        if not os.path.exists("{}/reports/nmap".format(os.getcwd())):
            os.mkdir("{}/reports/nmap".format(os.getcwd()))
        
        os.system("{0} {1} -oN {2}/reports/nmap/{3}_nmap_report.txt".format(nmap_command, IPs_input, os.getcwd(), IPs_input))
        
    except KeyboardInterrupt:
        sys.exit("\n")
