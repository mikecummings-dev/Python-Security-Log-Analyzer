from datetime import date
import os
log_date = date.today()

#set to hold unique IP's
ip_set = set()
#Dict to hold failed login IP's and thier number of attempts
failed_ip_dict = {}
#num events counter
num_events = 0
#Failed login counter
failed_logins = 0
#Successful login counter
successful_logins = 0
#Collects file path from user
filepath = str(input("Please enter the file path for the log file you wish to analyze:"))
#collects name for report file to write to 
report_doc = str(input("Please enter the report file name you wish to create:"))
#sets varaible for open file
file = open(filepath, "r")
#Sets varaible for file name to use in report
log_file = os.path.basename(filepath)

#Parse each line in file
for line in file:
    #Each line is an event so add to event counter
    num_events +=1
    #Check if "from" in line to see if event is login attempt
    if "from" in line:
        #split line at from b/c ip is after from [1] to get second part of split str
        ip = line.split("from")[1].strip()
        #Add unique ip to set
        ip_set.add(ip)
        #check if failed log in attempt
        if "Failed login" in line:
            #Add to counter
            failed_logins +=1
            #Check if ip not in dict
            if ip not in failed_ip_dict:
                #add it with 1 attempt as its counter
                failed_ip_dict[ip] = 1
            #if it is already in dict
            else:
                #add to its counter
                failed_ip_dict[ip] += 1
        #check if succesful log in
        elif 'logged in ' in line:
            #Add to counter
            successful_logins += 1
            
#Get number of unique IPs
unique_ips = len(ip_set)
#Write report to report doc:
with open(report_doc, "w") as report:
    print("==================================================", file=report)
    print("             SECURITY ANALYSIS REPORT             ", file=report)
    print("==================================================", file=report)
    print(file=report)

    print("Analysis Date:", file=report)
    print(log_date, file=report)
    print(file=report)

    print("Log File:", file=report)
    print(log_file, file=report)
    print(file=report)

    print("--------------------------------------------------", file=report)
    print("GENERAL STATISTICS", file=report)
    print("--------------------------------------------------", file=report)
    print(file=report)

    print(f"Total Events: {num_events}", file=report)
    print(file=report)

    print(f"Successful Logins: {successful_logins}", file=report)
    print(f"Failed Logins: {failed_logins}", file=report)
    print(file=report)

    print(f"Unique IP Addresses: {unique_ips}", file=report)
    print(file=report)

    print("--------------------------------------------------", file=report)
    print("FAILED LOGIN SOURCES", file=report)
    print("--------------------------------------------------", file=report)
    print(file=report)

    for ip, count in sorted(
        failed_ip_dict.items(),
        key = lambda item: item[1],
        reverse=True
    ):
        print(f"{ip}: {count}", file=report)
        print(file=report)

    print("--------------------------------------------------", file=report)
    print("SUSPICIOUS ACTIVITY", file=report)
    print("--------------------------------------------------", file=report)
    print(file=report)

    def run_alert(ip, quantity):
        print("Alert:", file=report)
        print(f"{ip} exceeded threshold", file=report)
        print(file=report)
        print(f"Failed Attempts: {quantity}", file=report)
        print(file=report)

    for ip, quantity in failed_ip_dict.items():
        if quantity >= 5:
            run_alert(ip, quantity)

    print("--------------------------------------------------", file=report)
    print("END REPORT", file=report)
    print("--------------------------------------------------", file=report)









