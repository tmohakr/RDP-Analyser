import subprocess
import argparse
import os
import csv
import pandas as pd

# Function to run rdp-sec-check.pl for a given IP
def run_rdp_sec_check(ip, rdp_sec_check_dir):
    rdp_sec_check_path = os.path.join(rdp_sec_check_dir, "rdp-sec-check.pl")
    found_issues = []

    try:
        # Run the Perl script using subprocess and capture the output
        result = subprocess.run(
            ["perl", rdp_sec_check_path, f"{ip}:3389"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Check for any issue in the output
        for line in result.stdout.splitlines():
            if 'has issue' in line:
                issue = line.split('has issue', 1)[-1].strip().replace('_', ' ')
                found_issues.append(issue)
    
    except Exception as e:
        print(f"An error occurred while checking {ip}: {e}")
    
    return found_issues

# Function to read IPs from a file
def read_ips_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            return [line.strip() for line in file if line.strip()]
    except Exception as e:
        print(f"Error reading IP file: {e}")
        return []

# Function to save results in vertical format
def save_results_vertical(results):
    csv_file = "RDP_analyser_results.csv"
    xlsx_file = "RDP_analyser_results.xlsx"

    # Save to CSV
    with open(csv_file, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["IP Address", "Issues"])
        for ip, issues in results.items():
            writer.writerow([ip, ", ".join(issues)])

    # Save to XLSX
    df = pd.DataFrame([(ip, "; ".join(issues)) for ip, issues in results.items()],
                      columns=["IP Address", "Issues"])
    df.to_excel(xlsx_file, index=False)

# Function to save results in horizontal format
def save_results_horizontal(results):
    csv_file = "RDP_analyser_results.csv"
    xlsx_file = "RDP_analyser_results.xlsx"

    # Invert the results dictionary to group by issues
    issues_to_ips = {}
    for ip, issues in results.items():
        for issue in issues:
            if issue not in issues_to_ips:
                issues_to_ips[issue] = []
            issues_to_ips[issue].append(ip)

    # Determine the maximum number of IPs per issue
    max_ips = max(len(ips) for ips in issues_to_ips.values())

    # Create a DataFrame with issues as columns and IPs as rows
    data = {issue: ips + [''] * (max_ips - len(ips)) for issue, ips in issues_to_ips.items()}
    df = pd.DataFrame(data)

    # Save to CSV and XLSX
    df.to_csv(csv_file, index=False)
    df.to_excel(xlsx_file, index=False)

# Main function to handle arguments and run the checks
def main():
    parser = argparse.ArgumentParser(description="Run rdp-sec-check.pl on a list of IPs.")
    parser.add_argument("-f", "--file", required=True, help="Path to the file containing IPs")
    parser.add_argument("-d", "--dir", required=True, help="Directory where rdp-sec-check.pl is located")
    parser.add_argument("-o", "--orientation", choices=['horizontal', 'vertical'], default='vertical', 
                        help="Output format: 'horizontal' or 'vertical' (default: vertical)")

    args = parser.parse_args()

    # Read the IPs from the provided file
    ip_list = read_ips_from_file(args.file)
    
    # Dictionary to hold results
    results = {}

    # Run the check for each IP
    for ip in ip_list:
        issues = run_rdp_sec_check(ip, args.dir)
        if issues:
            results[ip] = issues

    # Save results based on orientation
    if args.orientation == 'horizontal':
        save_results_horizontal(results)
    else:
        save_results_vertical(results)

if __name__ == "__main__":
    main()
