#!/bin/bash

write_header() {
echo "NETWORK SECURITY SCAN REPORT"
}

input_validation() {
#Checking if the user input just one argument/ checking argument 

echo "Target IP Address/ Hostname: $TARGET_IP"

}

write_ports_section() {
local scan_results="$1"

echo "Be advised. This process may take 2-3 minutes to resolve"
#Open Ports and Detected Services
echo "Open Ports and Detected Services: "

echo "$scan_results" | grep "open"
##Running once in main function

}


write_vulns_section() {

local scan_results="$1"

echo "Potential Vulnerabilities Identified:"
#nmap scan appears in main and run once

echo "---Analyzing Service Versions---"
#need to call query_nvd within this function to define the appropriate variable line by line!
echo "$scan_results" | while read -r line; do
    if [[ "$line" =~ ^([0-9]+)/tcp[[:space:]]+open[[:space:]]+([^[:space:]]+)[[:space:]]+(.+)$ ]]; then

        port="${BASH_REMATCH[1]}"
        service="${BASH_REMATCH[2]}"
        version_info="${BASH_REMATCH[3]}"

        echo "Port: $port"
        echo "Service: $service"
        echo "Version Info: $version_info"

        query_nvd "$service" "$version_info" >> "$REPORT_FILE"
    fi
done
}

write_recs_section() {
  #generalized recommendations 
echo "Recommendations for Remediation:"
echo "Verify services and ports affected."
echo "Review detected vulnerabilities against NVD and other trusted sources"
echo "Employ role-based access control or network segmentation during analysis"
echo "Disable any services that are not essential"
echo "Perform scans to track and explore detected issues"

}

write_footer() {
DATE=$(date +%Y-%m-%d)
TIME=$(date +%H:%M:%S)

echo "Today's Date: $DATE"
echo "Current Time: $TIME"
echo "END OF REPORT"
}

#Adding query_nvd from assignment prompt
query_nvd() {
    local product="$1"
    local version="$2"
    # The NVD API is public but has rate limits. We'll request a small number of results.
    local results_limit=10
    
    echo # Add a newline for formatting
    echo "Querying NVD for vulnerabilities in: $product $version..."

    # The API needs a URL-encoded string. A simple space-to-%20 works for many cases.
    local search_query
    search_query=$(echo "$product $version" | sed 's/ /%20/g')

    local nvd_api_url="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${search_query}&resultsPerPage=${results_limit}"

    # Use curl to fetch the data (-s for silent) and jq to parse the JSON response.
    # We pipe the output of curl directly into jq.
    local vulnerabilities_json
    vulnerabilities_json=$(curl -s --connect-timeout 10 --max-time 30 "$nvd_api_url")
    
    if ! vulnerability_json=$(curl -s ... "$nvd_api_url"); then
        echo "[!] Error: NVD request failed."
        return 1
    fi


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
        echo "  [+] No vulnerabilities were returned by NVD for this keyword search."
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

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 $TARGET_IP" >&2
  exit 1
fi

#checks that the correct and needed services are installed/ pesent; if not, they are returning an error
for command in nmap curl jq; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "Error: $command is not installed." >&2
        exit 1
    fi
done

TARGET_IP="$1" # Store the first argument in a variable

#Target IP Address/ Hostname
#call for user input and request the input of the target IP address. This must be stored in a variable as well!

REPORT_FILE="report.txt"

#adding progress messages
echo "Running Nmap scan using target IP: $TARGET_IP ..." >&2
SCAN_RESULTS=$(nmap -sV -sC --script vuln "$TARGET_IP")
#indicates completed scan after scan resolves
echo "Nmap scan complete!" >&2

write_header > $REPORT_FILE
input_validation "$TARGET_IP" >> $REPORT_FILE
write_ports_section "$SCAN_RESULTS" >> $REPORT_FILE
write_vulns_section "$SCAN_RESULTS" >> $REPORT_FILE
write_recs_section >> $REPORT_FILE
write_footer >> $REPORT_FILE
}

#calling main function which has other functions embedded
main "$@"