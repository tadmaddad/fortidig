import re
import sys
from collections import Counter
from datetime import datetime

def compile_patterns():
    return {
        "CVE-2022-40684": re.compile(r'user="Local_Process_Access"'),
        "CVE-2022-41328": re.compile(r'execute wireless-controller hs20-icon upload-icon'),
        "CVE-2022-42475": re.compile(r'logdesc="Application crashed".*msg=".*application:sslvpnd,.*Signal 11 received, Backtrace:.*"', re.DOTALL),
        "CVE-2024-55591": re.compile(r'logdesc="Admin login successful".*ui="jsconsole".*srcip=(\d+\.\d+\.\d+\.\d+).*dstip=\1.*action="login".*status="success"')
    }

def intrusion_check(log_lines):
    patterns = compile_patterns()
    found_cves = {}
    found_logs = {}

    for line in log_lines:
        for cve, pattern in patterns.items():
            if pattern.search(line):
                found_cves.setdefault(cve, 0)
                found_cves[cve] += 1
                found_logs.setdefault(cve, []).append(line.strip())

    if found_cves:
        for cve, count in found_cves.items():
            print(f"\033[91mWarning: Possible intrusion detected due to {cve}. Detected in {count} lines.\033[0m")
            print("Matching logs:")
            for log in found_logs[cve]:
                print(f"  {log}")
            print("--------------------------------------------------")
    else:
        print("No signs of specified intrusions detected.")
        print("--------------------------------------------------")

def display_menu(first_time=True):
    if first_time:
        print("""
        ###############################################
        #             Fortigate Log Digger            #
        #                 Version: 1.0.2              #
        ###############################################
        """)
    print("Select the function:\n0. Exit\n1. Intrusion Check\n")

def main(log_file_path):
    try:
        with open(log_file_path, 'r') as file:
            log_lines = file.readlines()
    except FileNotFoundError:
        print(f"Error: The file {log_file_path} was not found.")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)
    
    first_time = True
    while True:
        display_menu(first_time)
        first_time = False
        choice = input("Enter your choice (0-1): ")
        print("")  
        if choice == '0':
            print("Exiting program.")
            break
        elif choice == '1':
            intrusion_check(log_lines)
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python fortidig.py <log_file_path>")
        sys.exit(1)
    main(sys.argv[1])
