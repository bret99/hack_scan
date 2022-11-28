import sys
import os
from censys_hack import censys_hack
from criminalip_hack import criminalip_hack
from shodan_hack import shodan_hack
from zoomeye_hack import zoomeye_hack
from nmap_hack import nmap_hack

def main_menu():
    try:
        print(
            "\033[1;90m\nHack Scanner \033[1;00mmodules:\n\n[\033[1;90m1\033[1;00m] Get \033[1;90mCensys\033[1;00m report\n[\033[1;90m2\033[1;00m] Get \033[1;90mCriminalIP\033[1;00m report\n[\033[1;90m3\033[1;00m] Get \033[1;90mShodan\033[1;00m report\n[\033[1;90m4\033[1;00m] Get \033[1;90mZoomeye\033[1;00m report\n[\033[1;90m5\033[1;00m] Get \033[1;90mNmap\033[1;00m report\n[\033[1;90m99\033[1;00m] \033[1;90mExit\033[1;00m\n"
        )
        choose_module = input("Enter module number: ")
        if choose_module == "1":
            censys_hack()
            main_menu()
        elif choose_module == "2":
            criminalip_hack()
            main_menu()
        elif choose_module == "3":
            shodan_hack()
            main_menu()
        elif choose_module == "4":
            zoomeye_hack()
            main_menu()
        elif choose_module == "5":
            nmap_hack()
            main_menu()
        elif choose_module == "99":
            sys.exit()
        else:
            sys.exit("\033[1;91mWrong input!\033[1;00m")
    except KeyboardInterrupt:
        sys.exit("\n")


main_menu()
