import re
import sys
from collections import Counter
from datetime import datetime

def compile_patterns():
    return {
        "CVE-2022-40684": re.compile(r'user="Local_Process_Access"'),
        "CVE-2022-41328": re.compile(r'execute wireless-controller hs20-icon upload-icon'),
        "CVE-2022-42475": re.compile(r'logdesc="Application crashed".*msg=".*application:sslvpnd,.*Signal 11 received, Backtrace:.*"', re.DOTALL),
    }

def hourly_analysis(log_lines):
    hourly_event_counts = Counter()
    for line in log_lines:
        date_time_search = re.search(r'date=(.*?) time=(.*?) ', line)
        if date_time_search:
            date_time_str = f"{date_time_search.group(1)} {date_time_search.group(2)}"
            log_datetime = datetime.strptime(date_time_str, '%Y-%m-%d %H:%M:%S')
            hour = log_datetime.strftime('%Y-%m-%d %H:00')
            hourly_event_counts[hour] += 1
    for hour, count in sorted(hourly_event_counts.items()):
        print(f"{hour}: {count} events")
    print("--------------------------------------------------")

def event_analysis(log_lines):
    event_type_counts = Counter()
    for line in log_lines:
        action_search = re.search(r'action="(.*?)"', line)
        if action_search:
            event_type = action_search.group(1)
            event_type_counts[event_type] += 1
    for event_type, count in event_type_counts.items():
        print(f"{event_type}: {count} events")
    print("--------------------------------------------------")

def intrusion_check(log_lines):
    patterns = compile_patterns()
    found_cves = {}
    for line in log_lines:
        for cve, pattern in patterns.items():
            if pattern.search(line):
                found_cves.setdefault(cve, 0)
                found_cves[cve] += 1
    if found_cves:
        for cve, count in found_cves.items():
            print(f"\033[91mWarning: Possible intrusion detected due to {cve}. Detected in {count} lines.\033[0m")
    else:
        print("No signs of specified intrusions detected.")
    print("--------------------------------------------------")

def display_menu(first_time=True):
    if first_time:
        print("""
        ###############################################
        #             Fortigate Log Digger            #
        #                 Version: 1.0.0               #
        ###############################################
        """)
    print("Select the function:\n0. Exit\n1. Hourly Analysis\n2. Event Analysis\n3. Intrusion Check\n")

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
        choice = input("Enter your choice (0-3): ")
        print("")  
        if choice == '0':
            print("Exiting program.")
            break
        elif choice == '1':
            hourly_analysis(log_lines)
        elif choice == '2':
            event_analysis(log_lines)
        elif choice == '3':
            intrusion_check(log_lines)
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python fortidig.py <log_file_path>")
        sys.exit(1)
    main(sys.argv[1])
