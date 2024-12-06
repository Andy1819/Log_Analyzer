import csv

class Loganalysis:
    def __init__(self, log_file):
        
        self.log_file = log_file #log file to read, path is given
        self.log_content = [] #making list of dictionaries -> message format is important!

    def count_req_ip(self):
        
        request_count = {}
        for entry in self.log_content:
            ip = entry['ip']
            request_count[ip] = request_count.get(ip, 0) + 1

        return sorted(request_count.items(), key=lambda x: x[1], reverse=True)

    def most_endpoint(self):
        
        endpoint_count = {}

        for entry in self.log_content:
            endpoint = entry['endpoint'].split(" ")[1]
            endpoint_count[endpoint] = endpoint_count.get(endpoint, 0) + 1

        return max(endpoint_count, key=endpoint_count.get), max(endpoint_count.values())

    def suspicious_activity(self, threshold=10):
        
        failed_attempts = {}
        for entry in self.log_content:
            
            if entry['http_response'] == '401':
                ip = entry['ip']
                failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

        suspicious_ips = {}
        for ip,count in failed_attempts.items():
            if count > threshold:
                suspicious_ips[ip] = count
        return suspicious_ips

    def save_to_csv(self, req_ip, most_endpoint, fault_act):
        
        with open('log_analysis_results.csv', 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            
            #Requests per IP
            writer.writerow(["Requests per IP"])
            writer.writerow(["IP Address", "Request Count"])
            for ip, count in req_ip:
                writer.writerow([ip, count])
            
            #Most Accessed Endpoint
            writer.writerow([])
            writer.writerow(["Most Accessed Endpoint"])
            writer.writerow(["Endpoint", "Access Count"])
            writer.writerow(most_endpoint)
            
            #Suspicious Activities
            writer.writerow([])
            writer.writerow(["Suspicious Activity"])
            writer.writerow(["IP Address", "Failed Login Count"])
            for ip, count in fault_act.items():
                writer.writerow([ip, count])

    def parse_log(self):
        
        with open(self.log_file,'r') as file:
            for line in file:
                end_ip = line.find(' - - ')
                ip = line[:end_ip]

                start_date = line.find('[')
                end_date = line.find(']')
                date = line[start_date+1 : end_date]

                start_endpoint = line.find('"')
                end_endpoint = line.find('HTTP')
                endpoint = line[start_endpoint + 1 : end_endpoint]
                # print(endpoint)

                new_format = line[end_endpoint:].rstrip() #remove end lines so we are using rstrip()
                start_http = new_format.find('"')
                remaining = new_format[start_http + 2 : ].split(' ')
                http_response = remaining[0]
                size = remaining[1]

                self.log_content.append({
                    'ip': ip,
                    'date': date,
                    'endpoint': endpoint,
                    'http_response': http_response,
                    'size': size,
                })


if __name__ == "__main__":
    log_file_path = "sample.log"
    parser = Loganalysis(log_file_path)
    parser.parse_log()


    req_ip = parser.count_req_ip()
    print("Requests per IP:")
    print("IP Address     Request Count")
    for ip, count in req_ip:
        print(f"{ip}        {count}")


    most_endpoint = parser.most_endpoint()
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_endpoint[0]} (Accessed {most_endpoint[1]} times)")


    fault_act = parser.suspicious_activity(1)
    print("\nSuspicious Activity Detected:")
    print("IP Address       Failed Login Attempts")
    for ip, count in fault_act.items():
        print(f"{ip}      {count}")


    parser.save_to_csv(req_ip, most_endpoint, fault_act)
    print("\nResults saved to 'log_analysis_results.csv'.")
