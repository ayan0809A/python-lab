import re
import json
import csv
from collections import defaultdict
from collections import Counter
log_data = '''
192.168.1.10 - - [05/Dec/2020:14:15:45 +0000] "POST /login HTTP/1.1" 200 5320
192.168.1.11 - - [05/Dec/2020:14:16:50 +0000] "POST /login HTTP/1.1" 401 2340
192.168.1.11 - - [05/Dec/2020:14:18:00 +0000] "POST /login HTTP/1.1" 401 2340
192.168.1.11 - - [05/Dec/2020:14:19:10 +0000] "POST /login HTTP/1.1" 401 2340
192.168.1.11 - - [05/Dec/2020:14:20:30 +0000] "POST /login HTTP/1.1" 401 2340
192.168.1.11 - - [05/Dec/2020:14:22:40 +0000] "GET /home HTTP/1.1" 200 3020
'''

# Regex ifadəsi
pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[.*\] "(?P<method>POST|GET|PUT|DELETE) .+ HTTP/\d\.\d" (?P<status>\d{3})'

# Uğursuz girişlərin sayını saxlamaq üçün struktur
failed_attempts = {}
detailed_logs = []

# Log məlumatlarını analiz etmək
matches = re.finditer(pattern, log_data)
for match in matches:
    ip = match.group("ip")
    status = match.group("status")
    
    # Yalnız status 401 olanları əlavə et
    if status == "401":
        if ip not in failed_attempts:
            failed_attempts[ip] = 0
        failed_attempts[ip] += 1
#uygunlugu yoxlamaq
matches = re.findall(pattern, log_data)

# Nəticələri çap etmək
for match in matches:
    ip, date, method = match
    print(f"IP: {ip}, Tarix: {date}, HTTP Metodu: {method}")

# Uğursuz girişlər üçün IP siyahısı
failed_ips = [match[0] for match in matches]
#ugursuz girislerin sayini saymaq
ip_counter = Counter(failed_ips)

# 5-dən çox uğursuz giriş cəhdi olan IP-ləri seçmək
frequent_failed_ips = {ip: count for ip, count in ip_counter.items() if count > 5}

# Nəticəni JSON formatında saxlamaq
output_file = "failed_attempts.json"
with open(output_file, "w") as json_file:
    json.dump(frequent_failed_ips, json_file, indent=4)

print(f"5-dən çox uğursuz giriş cəhdi olan IP-lər JSON faylında saxlanıldı: {output_file}")
print(ip_counter)
# 5-dən çox uğursuz giriş cəhdi olanları seçmək
frequent_failed_ips = {ip: count for ip, count in ip_counter.items() if count > 5}

# Nəticəni mətn faylına yazmaq
output_file_txt = "failed_attempts.txt"
with open(output_file_txt, "w") as file:
    for ip, count in frequent_failed_ips.items():
        file.write(f"IP: {ip}, Cəhdlərin sayı: {count}\n")

print(f"Uğursuz giriş cəhdləri olan IP-lar mətn faylında saxlanıldı: {output_file_txt}")
#detallari cvv faylina yazmaq
log_analysis_csv = "log_analysis.csv"
with open(log_analysis_csv, "w", newline="") as csvfile:
    fieldnames = ["IP", "Date", "Method", "Failed"]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(detailed_logs)
print(log_analysis_csv)

# Təhdid kaşfiyyatı üçün nümunə IP siyahısı
threat_ips = ["192.168.1.1", "203.0.113.0", "10.0.0.1"]  # Nümunə təhdid IP-ləri
matched_threats = [ip for ip in failed_attempts if ip in threat_ips]

# Təhdid kaşfiyyatı IP-lərini JSON faylına yazırıq
threat_ips_file = "threat_ips.json"
with open(threat_ips_file, "w") as file:
    json.dump(matched_threats, file, indent=4)
print(threat_ips)
#ugursuz girisler ve tehdid kesfiyyatini birlesdiririk
combined_data = {
    "Failed Logins": frequent_failed_ips,
    "Threat IPs": matched_threats,
}
combined_security_data_file = "combined_security_data.json"
with open(combined_security_data_file, "w") as file:
    json.dump(combined_data, file, indent=4)
print(combined_data)

print("Tapşiriq yerinə yetirildi")
