#!/bin/bash

write_header() {
echo "NETWORK SECURITY SCAN REPORT"
}

input_validation() {
#Checking if the user input just one argument/ checking argument 
#count
if [ "$#" -lt 1 ]; then
  echo "Usage: $0 $TARGET_IP" >&2
  #exit 1
fi
 TARGET_IP="$1" # Store the first argument in a variable

#Target IP Address/ Hostname
#call for user input and request the input of the target IP address. This must be stored in a variable as well!

read -r -p "Please enter target IP address: " TARGET_IP

echo "Target IP Address/ Hostname: $TARGET_IP"
}

#sudo nmap -sV -sC --script vuln -oX temp_scan_results.xml $TARGET_IP

write_ports_section() {
#Open Ports and Detected Services
echo "Open Ports and Detected Services: "
echo "Example: Port 80/ tcp - http"
echo "Be advised. This process may take 2-3 minutes to resolve"
sudo nmap -sV -sC --script vuln $TARGET_IP | grep "open"
#sudo nmap -sV -sC --script vuln $TARGET_IP | grep "open"
}

write_vulns_section() {
SCAN_RESULTS=$(sudo nmap -sV -sC --script vuln $TARGET_IP | grep "open")
  #nmap -sV --script vuln "$TARGET_IP"
echo "Potential Vulnerabilities Identified:"
echo "$SCAN_RESULTS" | grep "VULNERABLE"
echo "Sample data: CVE-2023-XXXX - Outdated Web Server"
echo "Sample data: Default Credentials - FTP Server"

}

write_recs_section() {
echo "Recommendations for Remediation"
echo "Update all software to the latest versions."
}

write_footer() {
DATE=$(date +%Y-%m-%d)
TIME=$(date +%H:%M:%S)

echo "Today's Date: $DATE"
echo "Current Time: $TIME"
echo "END OF REPORT"
}

main() {

REPORT_FILE="report.txt"

write_header > report.txt
input_validation >> report.txt
write_ports_section >> report.txt
write_vulns_section >> report.txt
write_recs_section >> report.txt
write_footer >> $REPORT_FILE
}

#calling main function which has other functions embedded
main "$@"
