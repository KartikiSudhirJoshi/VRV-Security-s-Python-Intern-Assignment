import re
import csv
from collections import defaultdict, Counter

# File paths
LOG_FILE = "sample.log"
OUTPUT_CSV = "log_analysis_results.csv"

# Configurable threshold for suspicious activity detection
FAILED_LOGIN_THRESHOLD = 10

def parse_log(file_path):
    """Parses the log file and returns a list of log entries."""
    with open(file_path, 'r') as file:
        logs = file.readlines()
    return logs

def count_requests_per_ip(logs):
    """Counts the number of requests per IP address and sorts them by request count."""
    ip_count = Counter()
    for log in logs:
        ip = log.split()[0]
        ip_count[ip] += 1
    # Sort by descending order of request count
    return dict(sorted(ip_count.items(), key=lambda x: x[1], reverse=True))

def find_most_accessed_endpoint(logs):
    """Finds the most frequently accessed endpoint."""
    endpoint_count = Counter()
    for log in logs:
        match = re.search(r'"(?:GET|POST|PUT|DELETE) (.*?) HTTP', log)
        if match:
            endpoint = match.group(1)
            endpoint_count[endpoint] += 1
    if endpoint_count:
        most_accessed = endpoint_count.most_common(1)[0]
        return most_accessed
    return ("None", 0)

def detect_suspicious_activity(logs, threshold=FAILED_LOGIN_THRESHOLD):
    """Detects IP addresses with failed login attempts exceeding the threshold."""
    failed_attempts = defaultdict(int)
    for log in logs:
        if "401" in log or "Invalid credentials" in log:
            ip = log.split()[0]
            failed_attempts[ip] += 1
    suspicious_ips = {ip: count for ip, count in failed_attempts.items() if count > threshold}
    return suspicious_ips

def save_to_csv(ip_counts, most_accessed_endpoint, suspicious_activity, output_file):
    """Saves analysis results to a CSV file."""
    with open(output_file, mode='w', newline='') as file:
        writer = csv.writer(file)

        # Write Requests per IP section
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])
        writer.writerow([])

        # Write Most Accessed Endpoint section
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow(most_accessed_endpoint)
        writer.writerow([])

        # Write Suspicious Activity section
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])

def main():

    """
    Main function to parse logs, perform analysis, display results, and save them to a CSV file.
    """
    # Parse log file
    logs = parse_log(LOG_FILE)

    # Perform analysis
    ip_counts = count_requests_per_ip(logs)
    most_accessed_endpoint = find_most_accessed_endpoint(logs)
    suspicious_activity = detect_suspicious_activity(logs)

    # Display results
    print("Requests per IP:")
    print("IP Address\t\tRequest Count")
    for ip, count in ip_counts.items():
        print(f"{ip}\t\t{count}")
    print("\nMost Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    print("\nSuspicious Activity Detected:")
    print("IP Address\t\tFailed Login Attempts")
    if suspicious_activity:
        for ip, count in suspicious_activity.items():
            print(f"{ip}\t\t{count}")
    else:
        print("None detected")

    # Save results to CSV
    save_to_csv(ip_counts, most_accessed_endpoint, suspicious_activity, OUTPUT_CSV)
    print(f"\nResults saved to {OUTPUT_CSV}")

if __name__ == "__main__":
    main()
