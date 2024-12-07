import re
import csv
from collections import Counter, defaultdict

# Configurable threshold for suspicious activity
FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(log_file):
    ip_request_counts = Counter()
    endpoint_counts = Counter()
    failed_login_attempts = defaultdict(int)

    with open(log_file, 'r') as file:
        for line in file:
            # Extract IP addresses
            ip_match = re.search(r'^(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                ip = ip_match.group(1)
                ip_request_counts[ip] += 1

            # Extract endpoints
            endpoint_match = re.search(r'"[A-Z]+\s(/[\w/]+)\s', line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_counts[endpoint] += 1

            # Detect failed login attempts (status code 401)
            if ' 401 ' in line or 'Invalid credentials' in line:
                if ip_match:
                    failed_login_attempts[ip] += 1

    return ip_request_counts, endpoint_counts, failed_login_attempts

def save_results_to_csv(ip_request_counts, most_accessed_endpoint, failed_login_attempts, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # Save Requests per IP
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_request_counts.items():
            writer.writerow([ip, count])

        # Save Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(["Most Frequently Accessed Endpoint", "Access Count"])
        writer.writerow(most_accessed_endpoint)

        # Save Suspicious Activity
        writer.writerow([])
        writer.writerow(["IP Address", "Failed Login Attempts"])
        for ip, count in failed_login_attempts.items():
            if count > FAILED_LOGIN_THRESHOLD:
                writer.writerow([ip, count])

def main():
    log_file = 'sample.log'
    output_file = 'log_analysis_results.csv'

    ip_request_counts, endpoint_counts, failed_login_attempts = parse_log_file(log_file)

    # Most Frequently Accessed Endpoint
    most_accessed_endpoint = endpoint_counts.most_common(1)[0]

    # Display Results
    print("IP Address           Request Count")
    for ip, count in ip_request_counts.items():
        print(f"{ip:20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in failed_login_attempts.items():
        if count > FAILED_LOGIN_THRESHOLD:
            print(f"{ip:20} {count}")

    # Save Results to CSV
    save_results_to_csv(ip_request_counts, most_accessed_endpoint, failed_login_attempts, output_file)
    print(f"\nResults saved to {output_file}")

if __name__ == "__main__":
    main()
