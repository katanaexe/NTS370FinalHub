#!/bin/bash

write_header() {
echo "NETWORK SECURITY SCAN REPORT"
}

input_validation() {
#Checking if the user input just one argument/ checking argument 
#count
#TARGET for testing is local 127.0.0.1
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
echo "Be advised. This process may take 2-3 minutes to resolve"
#Open Ports and Detected Services
echo "Open Ports and Detected Services: "
#echo "Example: Port 80/ tcp - http"

nmap -sV -sC --script vuln "$TARGET_IP"| grep "open"
#nmap -sV -sC --script vuln $TARGET_IP | grep "open"
#this edited out one was unquote/ did not call the target IP address correctly
}
echo "Be advised. This process may take 2-3 minutes to resolve"

write_vulns_section() {
echo "Potential Vulnerabilities Identified:"
SCAN_RESULTS=$(nmap -sV --script vuln "$TARGET_IP")
#echo "$SCAN_RESULTS"
#second run of nmap - editing out because it doubles the scan time; I added a run of nmap in updating this function rather than modifying
  #nmap -sV -sC--script vuln "$TARGET_IP"
echo "---Analyzing Service Versions---"
#need to call query_nvd within this function to define the appropriate variable line by line!
echo "$SCAN_RESULTS" | while read -r line; do
  case "$line" in
    #*Apache\ httpd\ 2.4.49*)
     # echo "[!!] VULNERABILITY DETECTED: Apache 2.4.49 is running, which is vulnerable to path traversal (CVE-2021-41773)."
      #query_nvd "Apache" "2.4.49"
      #;;
      #editing out to confirm that a null response is not triggering any unwanted results while I troubleshoot
    *OpenSSH\ 7.6p1*)
      echo "[!!] POTENTIAL VULNERABILITY: OpenSSH 7.6p1 detected. Lacks modern security flags and cipher defaults found in recent versions."
      #query_nvd "OpenSSH" "7.6p1"
      #this returned nothing from NVD and I wonder if it's just too specific on the version; trying 7.6 and keeping returned NVD result
      query_nvd "OpenSSH" "7.6"
      ;;
  esac
done
#query_nvd "$product_name" "$product_version">> "$REPORT_FILE"
#Remove the above run of query_nvd as it is likely pulling the null result because it has NO DEFINED VARIABLES, you silly goose (this is directed at myself, Dr. Becote)

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

#Adding query_nvd
query_nvd() {
    local product="$1"
    local version="$2"
    # The NVD API is public but has rate limits. We'll request a small number of results.
    local results_limit=3
    
    echo # Add a newline for formatting
    echo "Querying NVD for vulnerabilities in: $product $version..."

    # The API needs a URL-encoded string. A simple space-to-%20 works for many cases.
    local search_query
    search_query=$(echo "$product $version" | sed 's/ /%20/g')

    local nvd_api_url="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${search_query}&resultsPerPage=${results_limit}"

    # Use curl to fetch the data (-s for silent) and jq to parse the JSON response.
    # We pipe the output of curl directly into jq.
    local vulnerabilities_json
    vulnerabilities_json=$(curl -s "$nvd_api_url")

    # --- Defensive Programming: Check for Errors ---
    if [[ -z "$vulnerabilities_json" ]]; then
        echo "  [!] Error: Failed to fetch data from NVD. The API might be down or unreachable."
        return
    fi
    if echo "$vulnerabilities_json" | jq -e '.message' > /dev/null; then
        echo "  [!] NVD API Error: $(echo "$vulnerabilities_json" | jq -r '.message')"
        return
    fi
    if ! echo "$vulnerabilities_json" | jq -e '.vulnerabilities[0]' > /dev/null; then
        echo "  [+] No vulnerabilities found in NVD for this keyword search."
        return
    fi
    # --- End Error Checks ---

    # This jq command filters the JSON and formats it for our report.
    # It extracts the CVE ID, the English description, and the severity.
    echo "$vulnerabilities_json" | jq -r \
        '.vulnerabilities[] |
        "  CVE ID: \(.cve.id)\n  Description: \((.cve.descriptions[] | select(.lang=="en")).value | gsub("\n"; " "))\n  Severity: \(.cve.metrics.cvssMetricV31[0].cvssData.baseSeverity // .cve.metrics.cvssMetricV2[0].cvssData.baseSeverity // "N/A")\n---"'
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