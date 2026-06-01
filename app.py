from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, request, jsonify, send_file
import subprocess, platform, tempfile, os, re, socket, json, io, hmac, hashlib, time, sqlite3
from datetime import datetime
import requests as req
from urllib.parse import urlsplit

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

app = Flask(__name__)
app.secret_key = 'change-this-to-any-random-string-123'
from dotenv import load_dotenv
load_dotenv()

app.secret_key = os.getenv('SECRET_KEY')
app.config['GOOGLE_CLIENT_ID']     = os.getenv('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET')

from flask_login import LoginManager, login_required, current_user
from auth import auth, get_user_by_id, init_oauth

init_oauth(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please sign in to access the scanner.'

app.register_blueprint(auth)

@login_manager.user_loader
def load_user(user_id):
    return get_user_by_id(user_id)
# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────
GROQ_API_KEY        = os.getenv('GROQ_API_KEY')
RAZORPAY_KEY_ID     = os.environ.get('RAZORPAY_KEY_ID')
RAZORPAY_KEY_SECRET = os.environ.get('RAZORPAY_KEY_SECRET')
DB_PATH = os.environ.get('DB_PATH', 'mtvs_scans.db')

DATABASE_URL = os.environ.get('DATABASE_URL')

def get_connection():
    if DATABASE_URL:
        import psycopg2
        return psycopg2.connect(DATABASE_URL)
    return sqlite3.connect(DB_PATH)

def ph():
    return '%s' if DATABASE_URL else '?'
if os.path.dirname(DB_PATH):
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# DATABASE SETUP
# ─────────────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────
# DATABASE SETUP
# ─────────────────────────────────────────────────────────────────
DATABASE_URL = os.environ.get('DATABASE_URL')

def get_connection():
    if DATABASE_URL:
        import psycopg2
        return psycopg2.connect(DATABASE_URL)
    return sqlite3.connect(DB_PATH)

def ph():
    return '%s' if DATABASE_URL else '?'

def init_db():
    conn = get_connection()
    c    = conn.cursor()

    if DATABASE_URL:
        # PostgreSQL syntax
        c.execute('''CREATE TABLE IF NOT EXISTS scans (
            id           SERIAL PRIMARY KEY,
            target       TEXT NOT NULL,
            scan_time    TEXT NOT NULL,
            plan         TEXT DEFAULT 'basic',
            tools_used   TEXT,
            total_checks INTEGER DEFAULT 0,
            vuln_count   INTEGER DEFAULT 0,
            warn_count   INTEGER DEFAULT 0,
            ok_count     INTEGER DEFAULT 0,
            created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS scan_results (
            id           SERIAL PRIMARY KEY,
            scan_id      INTEGER NOT NULL,
            tool         TEXT NOT NULL,
            description  TEXT,
            category     TEXT,
            status       TEXT,
            output       TEXT,
            severity     TEXT,
            threat_level TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )''')
    else:
        # SQLite syntax
        c.execute('''CREATE TABLE IF NOT EXISTS scans (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            target       TEXT NOT NULL,
            scan_time    TEXT NOT NULL,
            plan         TEXT DEFAULT 'basic',
            tools_used   TEXT,
            total_checks INTEGER DEFAULT 0,
            vuln_count   INTEGER DEFAULT 0,
            warn_count   INTEGER DEFAULT 0,
            ok_count     INTEGER DEFAULT 0,
            created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS scan_results (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id      INTEGER NOT NULL,
            tool         TEXT NOT NULL,
            description  TEXT,
            category     TEXT,
            status       TEXT,
            output       TEXT,
            severity     TEXT,
            threat_level TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )''')

    conn.commit()
    conn.close()

init_db()


def save_scan_to_db(target, results, plan, scan_time):
    conn = get_connection()
    c    = conn.cursor()

    vuln_count = sum(1 for r in results if "[VULNERABLE]" in r.get("output","") or "[MISSING]" in r.get("output",""))
    warn_count = sum(1 for r in results if "[WARN]" in r.get("output",""))
    ok_count   = sum(1 for r in results if r.get("status") == "completed")
    tools_used = ",".join([r.get("tool","") for r in results])

    c.execute(f'''INSERT INTO scans 
                 (target, scan_time, plan, tools_used, total_checks, vuln_count, warn_count, ok_count)
                 VALUES ({ph()},{ph()},{ph()},{ph()},{ph()},{ph()},{ph()},{ph()})''',
              (target, scan_time, plan, tools_used, len(results), vuln_count, warn_count, ok_count))

    if DATABASE_URL:
        c.execute("SELECT lastval()")
    scan_id = c.fetchone()[0] if DATABASE_URL else c.lastrowid

    for r in results:
        sev, _  = _severity(r)
        threat  = get_threat_level(r)
        c.execute(f'''INSERT INTO scan_results 
                     (scan_id, tool, description, category, status, output, severity, threat_level)
                     VALUES ({ph()},{ph()},{ph()},{ph()},{ph()},{ph()},{ph()},{ph()})''',
                  (scan_id, r.get("tool",""), r.get("description",""), r.get("category",""),
                   r.get("status",""), r.get("output",""), sev, threat["level"]))

    conn.commit()
    conn.close()
    return scan_id


def get_scan_history(limit=50):
    conn = get_connection()
    c    = conn.cursor()
    c.execute(f'''SELECT id, target, scan_time, plan, total_checks, 
                         vuln_count, warn_count, ok_count, created_at
                  FROM scans 
                  ORDER BY created_at DESC 
                  LIMIT {ph()}''', (limit,))
    rows = c.fetchall()
    conn.close()
    return [{"id":r[0], "target":r[1], "scan_time":r[2], "plan":r[3],
             "total_checks":r[4], "vuln_count":r[5], "warn_count":r[6],
             "ok_count":r[7], "created_at":r[8]} for r in rows]


def get_scan_detail(scan_id):
    conn = get_connection()
    c    = conn.cursor()

    c.execute(f'SELECT * FROM scans WHERE id={ph()}', (scan_id,))
    scan = c.fetchone()

    c.execute(f'SELECT * FROM scan_results WHERE scan_id={ph()}', (scan_id,))
    results = c.fetchall()
    conn.close()

    if not scan:
        return None

    return {
        "scan": {
            "id":           scan[0],
            "target":       scan[1],
            "scan_time":    scan[2],
            "plan":         scan[3],
            "tools_used":   scan[4],
            "total_checks": scan[5],
            "vuln_count":   scan[6],
            "warn_count":   scan[7],
            "ok_count":     scan[8]
        },
        "results": [
            {
                "id":          r[0],
                "scan_id":     r[1],
                "tool":        r[2],
                "description": r[3],
                "category":    r[4],
                "status":      r[5],
                "output":      r[6],
                "severity":    r[7],
                "threat_level":r[8]
            }
            for r in results
        ]
    }
# ─────────────────────────────────────────────────────────────────────────────
# THREAT INTELLIGENCE DATABASE
# ─────────────────────────────────────────────────────────────────────────────
THREAT_INTEL = {
    "http_headers": {
        "name": "HTTP Security Headers",
        "what": "HTTP security headers are response headers that instruct the browser on how to behave when handling your website's content. Missing headers leave users vulnerable to a range of client-side attacks.",
        "why": "Without these headers, attackers can inject malicious scripts (XSS), embed your site in iframes to steal clicks (Clickjacking), sniff content types, or downgrade HTTPS to HTTP connections.",
        "fix": "Add the following to your web server config:\n• X-Frame-Options: DENY\n• X-XSS-Protection: 1; mode=block\n• X-Content-Type-Options: nosniff\n• Strict-Transport-Security: max-age=31536000; includeSubDomains\n• Content-Security-Policy: default-src 'self'\n• Referrer-Policy: strict-origin-when-cross-origin",
        "cve": "CWE-693 (Protection Mechanism Failure)",
        "severity": "MEDIUM"
    },
    "https_redirect": {
        "name": "HTTPS Redirect Check",
        "what": "Checks whether the server properly redirects all HTTP traffic to HTTPS, ensuring all data in transit is encrypted.",
        "why": "Without forced HTTPS, attackers can perform Man-in-the-Middle (MITM) attacks, intercept sensitive data like passwords, session tokens, and personal information sent over plain HTTP.",
        "fix": "Configure your server to redirect all HTTP (port 80) requests to HTTPS (port 443).\n• Apache: RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n• Nginx: return 301 https://$host$request_uri;\n• Also enable HSTS header to prevent future HTTP access.",
        "cve": "CWE-319 (Cleartext Transmission of Sensitive Information)",
        "severity": "HIGH"
    },
    "cors": {
        "name": "CORS Policy",
        "what": "Cross-Origin Resource Sharing (CORS) controls which external domains can make requests to your API/site. Misconfigured CORS can expose your API to any website.",
        "why": "An overly permissive CORS policy (Access-Control-Allow-Origin: *) allows malicious websites to make authenticated API calls on behalf of logged-in users, potentially stealing data or performing actions without consent.",
        "fix": "• Never use wildcard (*) with credentials\n• Whitelist only trusted domains explicitly\n• Validate Origin header server-side\n• Set Access-Control-Allow-Origin to specific trusted domains\n• Review all CORS headers in your server config",
        "cve": "CWE-942 (Permissive Cross-domain Policy)",
        "severity": "MEDIUM"
    },
    "robots": {
        "name": "robots.txt / Sitemap Exposure",
        "what": "robots.txt tells search engine crawlers which pages to index. While not a security control, it often inadvertently reveals sensitive paths, admin panels, or hidden endpoints.",
        "why": "Attackers read robots.txt to discover restricted paths (e.g., /admin, /backup, /internal-api) that you're trying to hide from search engines. This is the Streisand Effect — trying to hide something actually advertises it.",
        "fix": "• Don't use robots.txt as a security control — it's public!\n• Remove sensitive path listings from robots.txt\n• Protect sensitive endpoints with authentication instead\n• Use robots.txt only for SEO purposes\n• Secure all admin/API endpoints regardless of robots.txt",
        "cve": "CWE-200 (Exposure of Sensitive Information)",
        "severity": "LOW"
    },
    "open_dirs": {
        "name": "Sensitive Path Exposure",
        "what": "Checks for publicly accessible sensitive files and directories like .git, .env, config.php, /admin, /backup, etc. These often contain credentials, source code, or configuration data.",
        "why": "Exposed .git directories allow attackers to download your entire source code. .env files contain database passwords and API keys. /backup folders may contain SQL dumps with all user data. These are critical, easily exploitable vulnerabilities.",
        "fix": "• Block access to .git, .env, .htaccess in your web server config\n• Never deploy .env files to web-accessible directories\n• Configure Nginx/Apache to deny dotfiles\n• Move backups outside the webroot\n• Use .htaccess: Deny from all for sensitive dirs\n• Regularly audit what's accessible from the web",
        "cve": "CWE-538 (Insertion of Sensitive Information into Externally-Accessible File)",
        "severity": "CRITICAL"
    },
    "ipv6": {
        "name": "IPv6 Configuration",
        "what": "Checks whether the server has IPv6 addresses configured. IPv6 is the modern Internet Protocol that will eventually replace IPv4.",
        "why": "While not a vulnerability, servers without IPv6 may have inconsistent security policies between IPv4 and IPv6 interfaces. Some firewall rules apply only to IPv4, leaving IPv6 interfaces unprotected.",
        "fix": "• Enable IPv6 on your server and networking equipment\n• Ensure firewall rules apply to both IPv4 and IPv6\n• Test your IPv6 configuration at test-ipv6.com\n• If IPv6 is not needed, explicitly disable it to reduce attack surface",
        "cve": "CWE-1188 (Initialization of a Resource with an Insecure Default)",
        "severity": "INFO"
    },
    "wordpress": {
        "name": "WordPress Detection",
        "what": "Detects WordPress installation indicators (wp-admin, wp-login.php, wp-content). WordPress powers ~43% of the web and is a frequent target due to plugin vulnerabilities.",
        "why": "Exposed WordPress admin panels are brute-forced constantly. Outdated plugins/themes contain known CVEs. wp-config.php leaks expose database credentials. XML-RPC can enable DDoS amplification.",
        "fix": "• Keep WordPress core, plugins, and themes updated\n• Rename or restrict access to /wp-admin\n• Disable XML-RPC if not needed\n• Use two-factor authentication on admin accounts\n• Install a security plugin (Wordfence, Sucuri)\n• Disable file editing from Dashboard → Appearance → Editor",
        "cve": "Multiple WordPress CVEs — check wpscan.com",
        "severity": "MEDIUM"
    },
    "drupal": {
        "name": "Drupal Detection",
        "what": "Detects Drupal CMS installation. Drupal has had several critical vulnerabilities including Drupalgeddon (SA-CORE-2018-002) that allowed unauthenticated RCE.",
        "why": "Unpatched Drupal installations are actively exploited. Drupalgeddon2 and Drupalgeddon3 (CVE-2018-7600, CVE-2018-7602) allowed complete server takeover without authentication.",
        "fix": "• Keep Drupal core updated immediately when security releases drop\n• Subscribe to Drupal security advisories\n• Remove /CHANGELOG.txt to hide version info\n• Run Drupal's Security Review module\n• Restrict admin paths in server config",
        "cve": "CVE-2018-7600 (Drupalgeddon2), CVE-2018-7602",
        "severity": "MEDIUM"
    },
    "joomla": {
        "name": "Joomla Detection",
        "what": "Detects Joomla CMS installation. Joomla is a popular CMS with a history of SQL injection and authentication bypass vulnerabilities.",
        "why": "Exposed Joomla admin panels (/administrator) are targeted by automated bots. Several versions had SQLi vulnerabilities allowing database extraction without authentication.",
        "fix": "• Keep Joomla updated to the latest stable release\n• Protect /administrator with IP whitelist or 2FA\n• Remove version information from page source\n• Use Joomla Security Checklist\n• Audit and remove unused extensions",
        "cve": "CVE-2015-8562 (RCE), CVE-2017-8917 (SQLi)",
        "severity": "MEDIUM"
    },
    "aspnet": {
        "name": "ASP.NET Misconfiguration",
        "what": "Checks if ASP.NET is exposing stack traces and error details publicly. Verbose error messages reveal framework versions, file paths, and code snippets to attackers.",
        "why": "Detailed error messages help attackers understand your application structure, identify technologies, and craft targeted exploits. Version information in error pages allows lookup of known CVEs.",
        "fix": "• Set customErrors mode='On' in web.config\n• Set <deployment retail='true' /> in machine.config\n• Never show detailed errors in production\n• Log errors server-side, show generic messages to users\n• Remove Server and X-Powered-By headers",
        "cve": "CWE-209 (Information Exposure Through an Error Message)",
        "severity": "MEDIUM"
    },
    "elmah": {
        "name": "ELMAH Logger Exposure",
        "what": "ELMAH (Error Logging Modules and Handlers) is an ASP.NET error logging library. If /elmah.axd is publicly accessible, attackers can view all application errors including stack traces, SQL queries, and connection strings.",
        "why": "Exposed ELMAH logs are a goldmine for attackers — they contain exception details, database queries (sometimes with passwords), internal file paths, user session data, and the full history of application errors.",
        "fix": "• Restrict ELMAH to localhost or admin IPs in web.config:\n  <location path='elmah.axd'><system.web><authorization><allow roles='admin'/><deny users='*'/></authorization></system.web></location>\n• Or disable the HTTP handler entirely in production\n• Consider removing ELMAH from production deployments",
        "cve": "CWE-532 (Insertion of Sensitive Information into Log File)",
        "severity": "HIGH"
    },
    "nmap_heartbleed": {
        "name": "Heartbleed (CVE-2014-0160)",
        "what": "Heartbleed is a critical vulnerability in OpenSSL's TLS heartbeat extension that allows attackers to read 64KB chunks of server memory per request, leaking private keys, passwords, and session tokens.",
        "why": "This is one of the most severe vulnerabilities ever discovered. An attacker can silently steal the server's private SSL key (allowing decryption of all past/future traffic), usernames, passwords, session cookies, and any sensitive data in memory.",
        "fix": "• Immediately upgrade OpenSSL to 1.0.1g or higher\n• Regenerate all SSL certificates and private keys\n• Revoke old certificates\n• Force all users to change passwords\n• Invalidate all active session tokens\n• Check if your distro has a patched package",
        "cve": "CVE-2014-0160 — CVSS 7.5 CRITICAL",
        "severity": "CRITICAL"
    },
    "nmap_poodle": {
        "name": "POODLE Attack",
        "what": "POODLE (Padding Oracle On Downgraded Legacy Encryption) exploits SSL 3.0's CBC padding to decrypt HTTPS cookies. Attackers force browsers to downgrade from TLS to vulnerable SSL 3.0.",
        "why": "If an attacker can perform a MITM attack, they can force SSL 3.0 downgrade and decrypt session cookies, effectively stealing authenticated sessions and impersonating users.",
        "fix": "• Disable SSL 3.0 entirely on your server\n• Nginx: ssl_protocols TLSv1.2 TLSv1.3;\n• Apache: SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1\n• Enable TLS_FALLBACK_SCSV to prevent downgrade attacks\n• Test at ssllabs.com/ssltest",
        "cve": "CVE-2014-3566 — CVSS 3.4 MEDIUM",
        "severity": "HIGH"
    },
    "nmap_smb_vuln": {
        "name": "EternalBlue / MS17-010 (WannaCry)",
        "what": "EternalBlue is an NSA exploit targeting a critical buffer overflow in Windows SMBv1. It was leaked by Shadow Brokers and weaponized as WannaCry and NotPetya ransomware.",
        "why": "This vulnerability allows unauthenticated remote code execution as SYSTEM. WannaCry infected 200,000+ systems in 150 countries in 2017. Any unpatched Windows system with SMB exposed is trivially compromised.",
        "fix": "• Apply MS17-010 security patch immediately\n• Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false\n• Block SMB ports (445, 137-139) at firewall\n• Never expose SMB to the internet\n• Use Windows Defender or EDR solutions",
        "cve": "CVE-2017-0144 — CVSS 9.8 CRITICAL",
        "severity": "CRITICAL"
    },
    "nmap_ssl_cert": {
        "name": "SSL Certificate Info",
        "what": "Retrieves and analyzes the SSL/TLS certificate — expiry date, issuer, subject, and validity. Expired or self-signed certificates break trust and can indicate security issues.",
        "why": "Expired certificates cause browser warnings that train users to click through security alerts. Self-signed certificates allow easy MITM attacks. Short-lived certificates may miss revocation.",
        "fix": "• Renew certificates before expiration (set calendar reminders at 60/30 days)\n• Use Let's Encrypt for free auto-renewing certificates\n• Use certificate pinning for high-value applications\n• Monitor expiry with tools like certbot or uptime monitors",
        "cve": "CWE-298 (Improper Validation of Certificate Expiration)",
        "severity": "MEDIUM"
    },
    "nmap_basic": {
        "name": "Port Scan (Fast)",
        "what": "Scans the top 100 most common TCP ports to discover which services are running and potentially exposed to the internet.",
        "why": "Every open port is an attack surface. Unnecessary services (FTP, Telnet, old databases) running publicly greatly increase the chances of exploitation, especially if unpatched.",
        "fix": "• Close all ports not required for the application\n• Use a firewall (UFW, iptables, cloud security groups) to restrict port access\n• Apply principle of least privilege — only expose what's needed\n• Move admin services behind VPN\n• Audit open ports regularly",
        "cve": "CWE-1052 (Excessive Platform Resource Consumption)",
        "severity": "INFO"
    },
    "nmap_ftp": {
        "name": "FTP Anonymous Login",
        "what": "Checks if the FTP server allows anonymous login (no credentials required) and tests for FTP bounce attack capability.",
        "why": "Anonymous FTP allows anyone to browse and potentially download/upload files without authentication. FTP also transmits credentials in plaintext, vulnerable to sniffing. FTP bounce can be used to port-scan internal networks.",
        "fix": "• Disable anonymous FTP login\n• Replace FTP with SFTP (SSH File Transfer Protocol)\n• If FTP is necessary, use FTPS (FTP over SSL)\n• Restrict FTP to specific IP addresses\n• Block port 21 at firewall if FTP is not needed",
        "cve": "CWE-287 (Improper Authentication)",
        "severity": "HIGH"
    },
    "nmap_ssh": {
        "name": "SSH Algorithm Enumeration",
        "what": "Enumerates SSH server's supported encryption algorithms, key exchange methods, and MAC algorithms to identify weak or deprecated cryptographic choices.",
        "why": "Weak SSH algorithms (MD5 MACs, arcfour ciphers, diffie-hellman-group1) can allow cryptographic attacks. Old algorithms may have known vulnerabilities allowing session decryption or authentication bypass.",
        "fix": "• Disable weak algorithms in /etc/ssh/sshd_config\n• KexAlgorithms curve25519-sha256,diffie-hellman-group14-sha256\n• Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\n• MACs hmac-sha2-256,hmac-sha2-512\n• Disable password authentication, use keys only\n• Use SSH version 2 only",
        "cve": "CVE-2023-48795 (Terrapin Attack)",
        "severity": "MEDIUM"
    },
    "nmap_http_enum": {
        "name": "Web Directory Enumeration",
        "what": "Enumerates web server directories and files using nmap's http-enum script, discovering hidden paths, admin panels, backup files, and sensitive endpoints.",
        "why": "Discovered admin panels without rate limiting are brute-forced. Backup files (.bak, .old, .zip) in webroot expose source code. Test endpoints left in production reveal application logic.",
        "fix": "• Remove all development/test files from production\n• Implement proper authentication on admin paths\n• Configure web server to return 404 for all unauthorized paths\n• Use Web Application Firewall (WAF) to block enumeration\n• Regularly audit accessible web paths",
        "cve": "CWE-548 (Exposure of Information Through Directory Listing)",
        "severity": "MEDIUM"
    },
    "ping": {
        "name": "Ping / Reachability",
        "what": "Basic ICMP echo request to check if the target host is online and reachable from the scanner.",
        "why": "While ping itself is benign, a responsive ICMP indicates the host is live, helping attackers confirm target validity before deeper scanning.",
        "fix": "• Consider blocking ICMP echo at the firewall to hide host existence (security through obscurity)\n• This is LOW priority — focus on real vulnerabilities first\n• Some networks require ICMP for path MTU discovery",
        "cve": "N/A — Informational",
        "severity": "INFO"
    },
    "whois": {
        "name": "WHOIS Lookup",
        "what": "Retrieves domain registration information including registrar, registration date, expiry, nameservers, and registrant contact information.",
        "why": "WHOIS data can expose personal contact information, reveal organization structure, show when domains expire (for hijacking), and identify hosting providers for targeted attacks.",
        "fix": "• Enable WHOIS privacy protection with your registrar\n• Use a privacy proxy email address\n• Monitor domain expiry dates to prevent hijacking\n• Use a registrar with strong account security (2FA)",
        "cve": "CWE-200 (Information Exposure)",
        "severity": "INFO"
    },
    "nmap_http_methods": {
        "name": "HTTP Methods Check",
        "what": "Identifies which HTTP methods the server accepts (GET, POST, PUT, DELETE, OPTIONS, TRACE, etc.). Dangerous methods like PUT and DELETE can allow file upload or deletion.",
        "why": "An enabled PUT method allows attackers to upload web shells directly to the server. TRACE enables Cross-Site Tracing (XST) attacks that can steal cookies even with HttpOnly flag set.",
        "fix": "• Disable unnecessary HTTP methods in server config\n• Apache: <LimitExcept GET POST> Deny from all </LimitExcept>\n• Nginx: if ($request_method !~ ^(GET|HEAD|POST)$) { return 444; }\n• Disable TRACE globally\n• Use Web Application Firewall",
        "cve": "CWE-650 (Trusting HTTP Permission Methods on the Server Side)",
        "severity": "HIGH"
    },
    "nmap_ccs": {
        "name": "CCS Injection (CVE-2014-0224)",
        "what": "The ChangeCipherSpec injection vulnerability in OpenSSL allows a MITM attacker to intercept and decrypt SSL/TLS encrypted communications between client and server.",
        "why": "An attacker between the client and server can inject a crafted CCS packet, causing both sides to use weak or no encryption, then decrypt and modify all traffic including sensitive credentials.",
        "fix": "• Update OpenSSL to version 1.0.1h or later (1.0.0m, 0.9.8za for older branches)\n• Patch your OS-provided OpenSSL package\n• Test at ssllabs.com after patching",
        "cve": "CVE-2014-0224 — CVSS 6.8 MEDIUM",
        "severity": "HIGH"
    },
    "nmap_freak": {
        "name": "FREAK / Cipher Enumeration",
        "what": "FREAK (Factoring RSA Export Keys) allows MITM attackers to force SSL/TLS to downgrade to weak 'export-grade' RSA encryption (512-bit) that can be factored in hours.",
        "why": "Once downgraded to export cipher suites, an attacker can factorize the weak 512-bit RSA key in ~7 hours on Amazon EC2, then decrypt all traffic including passwords and session tokens.",
        "fix": "• Disable all export cipher suites on the server\n• Disable SSLv2 and SSLv3\n• Use only TLS 1.2+ with strong ciphers\n• Nginx: ssl_ciphers 'ECDHE-RSA-AES256-GCM-SHA384:...';\n• Test with: openssl s_client -cipher EXPORT -connect host:443",
        "cve": "CVE-2015-0204 — CVSS 4.3 MEDIUM",
        "severity": "HIGH"
    },
    "nmap_logjam": {
        "name": "LOGJAM (Weak DH Params)",
        "what": "LOGJAM exploits servers using Diffie-Hellman key exchange with prime sizes of 512 or 1024 bits. Attackers can perform a MITM to downgrade connections to 512-bit 'export' DH.",
        "why": "Nation-state attackers have precomputed discrete logarithms for common 1024-bit DH primes (used by 18% of top sites). This allows real-time decryption of affected TLS sessions.",
        "fix": "• Generate a strong unique DH prime: openssl dhparam -out dhparam.pem 2048\n• Configure server to use 2048-bit+ DH parameters\n• Disable export cipher suites\n• Prefer ECDHE over DHE where possible\n• Test at weakdh.org",
        "cve": "CVE-2015-4000 — CVSS 3.7 LOW (but nation-state risk is HIGH)",
        "severity": "HIGH"
    }
}

def get_threat_intel(tool_key):
    return THREAT_INTEL.get(tool_key, {
        "name": tool_key.replace("_"," ").title(),
        "what": "This tool performs security reconnaissance on the target system.",
        "why": "Security issues discovered by this check may indicate vulnerabilities that could be exploited by attackers.",
        "fix": "Review the findings and consult security documentation for your specific technology stack.",
        "cve": "Refer to NIST NVD for CVE details",
        "severity": "INFO"
    })

def get_threat_level(result):
    output = result.get("output","")
    status = result.get("status","")
    if "[VULNERABLE]" in output: return {"level":"CRITICAL","color":"#ff2442","icon":"💀"}
    if "[MISSING]" in output:    return {"level":"HIGH",    "color":"#ff6b35","icon":"⚠️"}
    if "[WARN]" in output:       return {"level":"MEDIUM",  "color":"#ffd700","icon":"🔶"}
    if status == "completed":    return {"level":"LOW",     "color":"#00c853","icon":"✅"}
    return {"level":"INFO","color":"#00b0ff","icon":"ℹ️"}


# ─────────────────────────────────────────────────────────────────────────────
# PLAN DEFINITIONS
# ─────────────────────────────────────────────────────────────────────────────
PLANS = {
    "basic": {
        "name":        "Basic",
        "price_inr":   0,
        "price_paise": 0,
        "description": "Free tier with Python scans, PDF download, and AI Chatbot.",
        "pdf_access":  True,
        "chat_access": True,
        "tools":       "python_only",
    },
    "medium": {
        "name":        "Medium",
        "price_inr":   99,
        "price_paise": 9900,
        "description": "Unlock Nmap scans + medium-level security checks.",
        "pdf_access":  True,
        "chat_access": True,
        "tools":       "medium",
    },
    "pro": {
        "name":        "Pro",
        "price_inr":   199,
        "price_paise": 19900,
        "description": "All tools — full port scans, databases, SMB, firewall evasion.",
        "pdf_access":  True,
        "chat_access": True,
        "tools":       "all",
    },
}

PYTHON_TOOL_KEYS = [
    "http_headers","https_redirect","cors","robots",
    "open_dirs","ipv6","aspnet","elmah","wordpress","drupal","joomla",
]
MEDIUM_NMAP_KEYS = [
    "ping","whois","nmap_basic","nmap_top1000","nmap_version","nmap_ssl_cert","nmap_headers",
    "nmap_http_methods","nmap_http_auth","nmap_http_enum","nmap_heartbleed","nmap_poodle",
    "nmap_ccs","nmap_freak","nmap_logjam","nmap_ssh","nmap_ftp",
]
PLAN_TOOL_MAP = {
    "basic":  set(PYTHON_TOOL_KEYS),
    "medium": set(PYTHON_TOOL_KEYS + MEDIUM_NMAP_KEYS),
    "pro":    None,
}
VERIFIED_PAYMENTS = {}


def url_maker(url):
    if not re.match(r'http(s?)\:', url):
        url = 'http://' + url
    parsed = urlsplit(url)
    host = parsed.netloc
    if host.startswith('www.'):
        host = host[4:]
    return host


# ─────────────────────────────────────────────────────────────────────────────
# Python-native scan functions
# ─────────────────────────────────────────────────────────────────────────────
def scan_http_headers(target):
    try:
        r = req.get(f"http://{target}", timeout=10, allow_redirects=True)
        headers = r.headers
        findings = []
        checks = {
            "X-XSS-Protection":         "Missing X-XSS-Protection header",
            "X-Frame-Options":           "Missing X-Frame-Options header (Clickjacking risk)",
            "X-Content-Type-Options":    "Missing X-Content-Type-Options header",
            "Strict-Transport-Security": "Missing HSTS header",
            "Content-Security-Policy":   "Missing Content-Security-Policy header",
            "Referrer-Policy":           "Missing Referrer-Policy header",
        }
        for h, msg in checks.items():
            if h not in headers:
                findings.append(f"[MISSING] {msg}")
            else:
                findings.append(f"[OK]      {h}: {headers[h]}")
        server = headers.get("Server","")
        if server: findings.append(f"[INFO]    Server banner exposed: {server}")
        powered = headers.get("X-Powered-By","")
        if powered: findings.append(f"[INFO]    X-Powered-By exposed: {powered}")
        return "\n".join(findings)
    except Exception as e:
        return f"Error: {e}"

def scan_cms(target, cms):
    paths = {
        "wordpress": ["/wp-admin","/wp-login.php","/wp-content/"],
        "drupal":    ["/user/login","/sites/default/","/misc/drupal.js"],
        "joomla":    ["/administrator","/components/","/modules/"],
    }
    try:
        found = []
        for path in paths.get(cms,[]):
            r = req.get(f"http://{target}{path}", timeout=8, allow_redirects=False)
            if r.status_code in [200,301,302,403]:
                found.append(f"[FOUND] http://{target}{path} → {r.status_code}")
            else:
                found.append(f"[NOT FOUND] {path} → {r.status_code}")
        return "\n".join(found) if found else "No indicators found."
    except Exception as e:
        return f"Error: {e}"

def scan_aspnet(target):
    try:
        r = req.get(f"http://{target}/%7C~.aspx", timeout=8)
        if "Server Error" in r.text or "ASP.NET" in r.text or r.status_code==500:
            return f"[VULNERABLE] ASP.Net may be exposing stack errors (status {r.status_code})"
        return f"[OK] No ASP.Net misconfiguration detected (status {r.status_code})"
    except Exception as e:
        return f"Error: {e}"

def scan_elmah(target):
    try:
        r = req.get(f"http://{target}/elmah.axd", timeout=8)
        if r.status_code==200 and ("Error Log" in r.text or "elmah" in r.text.lower()):
            return "[VULNERABLE] Elmah error logger is publicly accessible!"
        return f"[OK] Elmah not exposed (status {r.status_code})"
    except Exception as e:
        return f"Error: {e}"

def scan_robots(target):
    results = []
    for path in ["/robots.txt","/sitemap.xml"]:
        try:
            r = req.get(f"http://{target}{path}", timeout=8)
            if r.status_code==200:
                results.append(f"[FOUND] {path}\n{r.text[:800]}")
            else:
                results.append(f"[NOT FOUND] {path} → {r.status_code}")
        except Exception as e:
            results.append(f"[ERROR] {path}: {e}")
    return "\n\n".join(results)

def scan_ipv6(target):
    try:
        results = socket.getaddrinfo(target,None)
        ipv6 = [r[4][0] for r in results if r[0]==socket.AF_INET6]
        ipv4 = [r[4][0] for r in results if r[0]==socket.AF_INET]
        out = []
        if ipv4: out.append(f"[INFO] IPv4: {', '.join(set(ipv4))}")
        if ipv6: out.append(f"[OK]   IPv6: {', '.join(set(ipv6))}")
        else: out.append("[INFO] No IPv6 address found")
        return "\n".join(out)
    except Exception as e:
        return f"Error: {e}"

def scan_open_dirs(target):
    paths = ["/.git/","/.env","/config.php","/admin/","/backup/","/db/","/.htaccess",
             "/phpinfo.php","/test/","/logs/","/api/","/swagger/","/actuator/","/console/","/.DS_Store"]
    found = []
    not_found = []
    try:
        for path in paths:
            r = req.get(f"http://{target}{path}", timeout=6, allow_redirects=False)
            if r.status_code in [200,403]:
                found.append(f"[FOUND] {path} → HTTP {r.status_code}")
            else:
                not_found.append(f"[OK]    {path} → {r.status_code}")
        result = ""
        if found:     result += "=== POTENTIALLY EXPOSED ===\n" + "\n".join(found)
        if not_found: result += "\n\n=== NOT FOUND ===\n" + "\n".join(not_found)
        return result.strip()
    except Exception as e:
        return f"Error: {e}"

def scan_https_redirect(target):
    try:
        r = req.get(f"http://{target}", timeout=8, allow_redirects=False)
        if r.status_code in [301,302,307,308]:
            loc = r.headers.get("Location","")
            if loc.startswith("https://"): return f"[OK] HTTP redirects to HTTPS → {loc}"
            return f"[WARN] HTTP redirects but NOT to HTTPS → {loc}"
        return f"[WARN] No HTTPS redirect detected (status {r.status_code})"
    except Exception as e:
        return f"Error: {e}"

def scan_cors(target):
    try:
        r = req.get(f"http://{target}", timeout=8, headers={"Origin":"https://evil.com"})
        acao = r.headers.get("Access-Control-Allow-Origin","")
        acac = r.headers.get("Access-Control-Allow-Credentials","")
        if acao=="*": return "[WARN] CORS allows all origins (Access-Control-Allow-Origin: *)"
        if acao=="https://evil.com": return f"[VULNERABLE] CORS reflects arbitrary origin!\nAllow-Origin: {acao}\nAllow-Credentials: {acac}"
        if acao: return f"[OK] CORS is restricted to: {acao}"
        return "[OK] No CORS headers present"
    except Exception as e:
        return f"Error: {e}"


# ─────────────────────────────────────────────────────────────────────────────
# Nmap scans
# ─────────────────────────────────────────────────────────────────────────────
SCANS = {
    "ping":               {"cmd": lambda t: f"ping -n 1 {t}" if platform.system()=="Windows" else f"ping -c 1 {t}", "desc":"Ping — reachability check","category":"Basic"},
    "whois":              {"cmd": lambda t: f"whois {t}",                                                             "desc":"WHOIS — domain registration info","category":"Basic"},
    "nmap_basic":         {"cmd": lambda t: f"nmap -F --open -Pn {t}",                                               "desc":"Nmap — fast top-100 port scan","category":"Port Scanning"},
    "nmap_top1000":       {"cmd": lambda t: f"nmap --top-ports 1000 --open -Pn {t}",                                 "desc":"Nmap — top 1000 ports scan","category":"Port Scanning"},
    "nmap_full_tcp":      {"cmd": lambda t: f"nmap -p1-65535 --open -Pn {t}",                                        "desc":"Nmap — full TCP port scan","category":"Port Scanning"},
    "nmap_full_udp":      {"cmd": lambda t: f"nmap -p1-65535 -sU --open -Pn {t}",                                    "desc":"Nmap — full UDP port scan","category":"Port Scanning"},
    "nmap_version":       {"cmd": lambda t: f"nmap -sV --version-intensity 5 -Pn {t}",                               "desc":"Nmap — service version detection","category":"Port Scanning"},
    "nmap_os":            {"cmd": lambda t: f"nmap -O --osscan-guess -Pn {t}",                                        "desc":"Nmap — OS fingerprinting","category":"Port Scanning"},
    "nmap_aggressive":    {"cmd": lambda t: f"nmap -A -Pn {t}",                                                      "desc":"Nmap — aggressive scan","category":"Port Scanning"},
    "nmap_traceroute":    {"cmd": lambda t: f"nmap --traceroute -Pn {t}",                                             "desc":"Nmap — traceroute","category":"Port Scanning"},
    "nmap_heartbleed":    {"cmd": lambda t: f"nmap -p443 --script ssl-heartbleed -Pn {t}",                            "desc":"Nmap — Heartbleed (CVE-2014-0160)","category":"SSL/TLS"},
    "nmap_poodle":        {"cmd": lambda t: f"nmap -p443 --script ssl-poodle -Pn {t}",                                "desc":"Nmap — POODLE SSL downgrade","category":"SSL/TLS"},
    "nmap_ccs":           {"cmd": lambda t: f"nmap -p443 --script ssl-ccs-injection -Pn {t}",                         "desc":"Nmap — CCS injection (CVE-2014-0224)","category":"SSL/TLS"},
    "nmap_freak":         {"cmd": lambda t: f"nmap -p443 --script ssl-enum-ciphers -Pn {t}",                          "desc":"Nmap — FREAK / cipher enumeration","category":"SSL/TLS"},
    "nmap_logjam":        {"cmd": lambda t: f"nmap -p443 --script ssl-dh-params -Pn {t}",                             "desc":"Nmap — LOGJAM (weak DH params)","category":"SSL/TLS"},
    "nmap_ssl_cert":      {"cmd": lambda t: f"nmap -p443 --script ssl-cert -Pn {t}",                                  "desc":"Nmap — SSL certificate info & expiry","category":"SSL/TLS"},
    "nmap_ssl_known_key": {"cmd": lambda t: f"nmap -p443 --script ssl-known-key -Pn {t}",                             "desc":"Nmap — known/compromised SSL key","category":"SSL/TLS"},
    "nmap_headers":       {"cmd": lambda t: f"nmap -p80 --script http-security-headers -Pn {t}",                      "desc":"Nmap — HTTP security headers","category":"HTTP/Web"},
    "nmap_iis":           {"cmd": lambda t: f"nmap -p80 --script=http-iis-webdav-vuln -Pn {t}",                       "desc":"Nmap — IIS WebDAV vulnerability","category":"HTTP/Web"},
    "nmap_http_methods":  {"cmd": lambda t: f"nmap -p80,443 --script http-methods -Pn {t}",                           "desc":"Nmap — allowed HTTP methods","category":"HTTP/Web"},
    "nmap_http_auth":     {"cmd": lambda t: f"nmap -p80,443 --script http-auth-finder -Pn {t}",                       "desc":"Nmap — HTTP auth mechanisms","category":"HTTP/Web"},
    "nmap_http_enum":     {"cmd": lambda t: f"nmap -p80,443 --script http-enum -Pn {t}",                              "desc":"Nmap — web directory enumeration","category":"HTTP/Web"},
    "nmap_http_shellshock":{"cmd": lambda t: f"nmap -p80,443 --script http-shellshock -Pn {t}",                       "desc":"Nmap — Shellshock (CVE-2014-6271)","category":"HTTP/Web"},
    "nmap_slowloris":     {"cmd": lambda t: f"nmap -p80,443 --script http-slowloris --max-parallelism 500 -Pn {t}",   "desc":"Nmap — Slowloris DoS","category":"HTTP/Web"},
    "nmap_snmp":          {"cmd": lambda t: f"nmap -p161 -sU --open -Pn {t}",                                         "desc":"Nmap — SNMP detection","category":"Network Services"},
    "nmap_ftp":           {"cmd": lambda t: f"nmap -p21 --script ftp-anon,ftp-bounce --open -Pn {t}",                 "desc":"Nmap — FTP anon login + bounce","category":"Network Services"},
    "nmap_telnet":        {"cmd": lambda t: f"nmap -p23 --open -Pn {t}",                                              "desc":"Nmap — Telnet detection","category":"Network Services"},
    "nmap_rdp_tcp":       {"cmd": lambda t: f"nmap -p3389 --open -sT -Pn {t}",                                        "desc":"Nmap — RDP over TCP","category":"Network Services"},
    "nmap_rdp_udp":       {"cmd": lambda t: f"nmap -p3389 --open -sU -Pn {t}",                                        "desc":"Nmap — RDP over UDP","category":"Network Services"},
    "nmap_ssh":           {"cmd": lambda t: f"nmap -p22 --script ssh2-enum-algos -Pn {t}",                            "desc":"Nmap — SSH algorithm enumeration","category":"Network Services"},
    "nmap_smtp":          {"cmd": lambda t: f"nmap -p25,465,587 --script smtp-open-relay,smtp-commands -Pn {t}",      "desc":"Nmap — SMTP open relay","category":"Network Services"},
    "nmap_dns":           {"cmd": lambda t: f"nmap -p53 --script dns-zone-transfer,dns-recursion -Pn {t}",            "desc":"Nmap — DNS zone transfer","category":"Network Services"},
    "nmap_mssql":         {"cmd": lambda t: f"nmap -p1433 --script ms-sql-info --open -Pn {t}",                       "desc":"Nmap — MS-SQL detection","category":"Databases"},
    "nmap_mysql":         {"cmd": lambda t: f"nmap -p3306 --script mysql-info --open -Pn {t}",                        "desc":"Nmap — MySQL detection","category":"Databases"},
    "nmap_oracle":        {"cmd": lambda t: f"nmap -p1521 --open -Pn {t}",                                            "desc":"Nmap — Oracle DB detection","category":"Databases"},
    "nmap_mongodb":       {"cmd": lambda t: f"nmap -p27017 --script mongodb-info --open -Pn {t}",                     "desc":"Nmap — MongoDB detection","category":"Databases"},
    "nmap_redis":         {"cmd": lambda t: f"nmap -p6379 --script redis-info --open -Pn {t}",                        "desc":"Nmap — Redis detection","category":"Databases"},
    "nmap_smb_tcp":       {"cmd": lambda t: f"nmap -p445,137-139 --script smb-security-mode --open -Pn {t}",          "desc":"Nmap — SMB security mode","category":"SMB/Windows"},
    "nmap_smb_udp":       {"cmd": lambda t: f"nmap -p137,138 --open -Pn {t}",                                         "desc":"Nmap — SMB over UDP","category":"SMB/Windows"},
    "nmap_smb_vuln":      {"cmd": lambda t: f"nmap -p445 --script smb-vuln-ms17-010 -Pn {t}",                         "desc":"Nmap — EternalBlue MS17-010","category":"SMB/Windows"},
    "nmap_smb_enum":      {"cmd": lambda t: f"nmap -p445 --script smb-enum-shares,smb-enum-users -Pn {t}",            "desc":"Nmap — SMB shares & users","category":"SMB/Windows"},
    "nmap_stuxnet":       {"cmd": lambda t: f"nmap --script stuxnet-detect -p445 -Pn {t}",                            "desc":"Nmap — Stuxnet detection","category":"SMB/Windows"},
    "nmap_firewall_acl":  {"cmd": lambda t: f"nmap -sA -Pn {t}",                                                      "desc":"Nmap — ACK scan (firewall)","category":"Firewall/IDS"},
    "nmap_firewall_detect":{"cmd": lambda t: f"nmap -sF -Pn {t}",                                                     "desc":"Nmap — FIN scan (IDS evasion)","category":"Firewall/IDS"},
    "nmap_fragmented":    {"cmd": lambda t: f"nmap -f -Pn {t}",                                                       "desc":"Nmap — fragmented packets","category":"Firewall/IDS"},
    "nmap_null_scan":     {"cmd": lambda t: f"nmap -sN -Pn {t}",                                                      "desc":"Nmap — NULL scan","category":"Firewall/IDS"},
}

TIMEOUTS = {
    "nmap_full_tcp":3600,"nmap_full_udp":4500,"nmap_slowloris":2700,
    "nmap_aggressive":600,"nmap_top1000":300,"nmap_basic":120,
    "nmap_http_enum":180,"nmap_smb_enum":120,
}

PYTHON_SCANS = {
    "http_headers":   {"fn":scan_http_headers,                 "desc":"HTTP security headers check","category":"Web Checks"},
    "https_redirect": {"fn":scan_https_redirect,               "desc":"HTTPS redirect check","category":"Web Checks"},
    "cors":           {"fn":scan_cors,                         "desc":"CORS policy check","category":"Web Checks"},
    "robots":         {"fn":scan_robots,                       "desc":"robots.txt / sitemap.xml","category":"Web Checks"},
    "open_dirs":      {"fn":scan_open_dirs,                    "desc":"Sensitive path exposure","category":"Web Checks"},
    "ipv6":           {"fn":scan_ipv6,                         "desc":"IPv6 address check","category":"Web Checks"},
    "aspnet":         {"fn":scan_aspnet,                       "desc":"ASP.Net misconfiguration","category":"CMS/Framework"},
    "elmah":          {"fn":scan_elmah,                        "desc":"Elmah logger exposure","category":"CMS/Framework"},
    "wordpress":      {"fn":lambda t:scan_cms(t,"wordpress"),  "desc":"WordPress check","category":"CMS/Framework"},
    "drupal":         {"fn":lambda t:scan_cms(t,"drupal"),     "desc":"Drupal check","category":"CMS/Framework"},
    "joomla":         {"fn":lambda t:scan_cms(t,"joomla"),     "desc":"Joomla check","category":"CMS/Framework"},
}


def run_scan(target, selected_tools):
    results = []
    tmp_dir = tempfile.gettempdir()
    for key in selected_tools:
        if key in PYTHON_SCANS:
            scan = PYTHON_SCANS[key]
            try:
                output = scan["fn"](target)
                results.append({"tool":key,"description":scan["desc"],"status":"completed",
                                 "output":output,"category":scan.get("category","Other"),
                                 "threat_intel":get_threat_intel(key),"threat_level":get_threat_level({"output":output,"status":"completed"})})
            except Exception as e:
                results.append({"tool":key,"description":scan["desc"],"status":"error",
                                 "output":str(e),"category":scan.get("category","Other"),
                                 "threat_intel":get_threat_intel(key),"threat_level":{"level":"ERROR","color":"#ff2442","icon":"❌"}})
            continue
        if key not in SCANS: continue
        scan = SCANS[key]
        cmd = scan["cmd"](target)
        timeout = TIMEOUTS.get(key,60)
        try:
            output = subprocess.check_output(cmd,shell=True,stderr=subprocess.STDOUT,timeout=timeout)
            r = {"tool":key,"description":scan["desc"],"status":"completed",
                 "output":output.decode(errors='replace'),"category":scan.get("category","Other"),
                 "threat_intel":get_threat_intel(key)}
            r["threat_level"] = get_threat_level(r)
            results.append(r)
        except subprocess.TimeoutExpired:
            results.append({"tool":key,"description":scan["desc"],"status":"timeout",
                             "output":"Scan timed out.","category":scan.get("category","Other"),
                             "threat_intel":get_threat_intel(key),"threat_level":{"level":"TIMEOUT","color":"#ffd700","icon":"⏱️"}})
        except subprocess.CalledProcessError as e:
            r = {"tool":key,"description":scan["desc"],"status":"error",
                 "output":e.output.decode(errors='replace'),"category":scan.get("category","Other"),
                 "threat_intel":get_threat_intel(key)}
            r["threat_level"] = get_threat_level(r)
            results.append(r)
        except Exception as e:
            results.append({"tool":key,"description":scan["desc"],"status":"unavailable",
                             "output":str(e),"category":scan.get("category","Other"),
                             "threat_intel":get_threat_intel(key),"threat_level":{"level":"N/A","color":"#556655","icon":"⚪"}})
    return results


def _severity(result):
    out    = result.get("output","")
    status = result.get("status","")
    if "[VULNERABLE]" in out or "[MISSING]" in out: return "HIGH",   colors.HexColor("#ff2442")
    if "[WARN]" in out:                              return "MEDIUM", colors.HexColor("#ffd700")
    if status == "completed":                        return "INFO",   colors.HexColor("#00b0ff")
    return "N/A", colors.HexColor("#556655")


# ─────────────────────────────────────────────────────────────────────────────
# PDF Generation
# ─────────────────────────────────────────────────────────────────────────────
C_BG=colors.HexColor("#0d1117"); C_GREEN=colors.HexColor("#00c853"); C_RED=colors.HexColor("#ff2442")
C_AMBER=colors.HexColor("#ffd700"); C_BLUE=colors.HexColor("#00b0ff"); C_GREY=colors.HexColor("#556655")
C_TEXT=colors.HexColor("#c8d8c8"); C_PANEL=colors.HexColor("#161b22"); C_BORDER=colors.HexColor("#1f2d1f")

def _styles():
    return dict(
        title=ParagraphStyle("t",fontName="Helvetica-Bold",fontSize=22,textColor=C_GREEN,spaceAfter=2,leading=26),
        sub=ParagraphStyle("s",fontName="Helvetica",fontSize=9,textColor=C_GREY,spaceAfter=0,leading=12),
        section=ParagraphStyle("sc",fontName="Helvetica-Bold",fontSize=11,textColor=C_GREEN,spaceBefore=14,spaceAfter=6,leading=14),
        meta_label=ParagraphStyle("ml",fontName="Helvetica-Bold",fontSize=7,textColor=C_GREY,spaceAfter=1,leading=10),
        meta_val=ParagraphStyle("mv",fontName="Helvetica",fontSize=9,textColor=C_BLUE,spaceAfter=0,leading=12),
        tool_name=ParagraphStyle("tn",fontName="Helvetica-Bold",fontSize=9,textColor=C_GREEN,spaceAfter=0,leading=11),
        tool_desc=ParagraphStyle("td",fontName="Helvetica-Oblique",fontSize=8,textColor=C_GREY,spaceAfter=0,leading=10),
        output=ParagraphStyle("o",fontName="Courier",fontSize=7.5,textColor=C_TEXT,spaceAfter=0,leading=10),
        threat_hdr=ParagraphStyle("th",fontName="Helvetica-Bold",fontSize=8,textColor=C_AMBER,spaceAfter=2,leading=11),
        threat_body=ParagraphStyle("tb",fontName="Helvetica",fontSize=7.5,textColor=C_TEXT,spaceAfter=0,leading=11),
        footer=ParagraphStyle("f",fontName="Helvetica",fontSize=7,textColor=C_GREY,spaceAfter=0,leading=9,alignment=TA_CENTER),
    )

def generate_pdf_report(target, results, scan_time, plan_name="Basic"):
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf,pagesize=A4,leftMargin=18*mm,rightMargin=18*mm,topMargin=18*mm,bottomMargin=18*mm)
    S = _styles()
    W = doc.width
    story = []

    story.append(Paragraph("Multi-Tool Web Vulnerability Scanner", S["title"]))
    story.append(Paragraph(f"Security Assessment Report  //  Confidential  //  Plan: {plan_name}", S["sub"]))
    story.append(HRFlowable(width="100%",thickness=1,color=C_GREEN,spaceAfter=8,spaceBefore=6))

    vuln_count = sum(1 for r in results if "[VULNERABLE]" in r.get("output","") or "[MISSING]" in r.get("output",""))
    warn_count = sum(1 for r in results if "[WARN]" in r.get("output",""))
    ok_count   = sum(1 for r in results if r.get("status")=="completed")
    err_count  = sum(1 for r in results if r.get("status") in ["error","timeout","unavailable"])

    meta_data = [
        [Paragraph("TARGET",S["meta_label"]),Paragraph("SCAN DATE",S["meta_label"]),Paragraph("TOTAL CHECKS",S["meta_label"]),Paragraph("TOOL VERSION",S["meta_label"])],
        [Paragraph(target,S["meta_val"]),Paragraph(scan_time,S["meta_val"]),Paragraph(str(len(results)),S["meta_val"]),Paragraph("MTVS v3.0",S["meta_val"])],
    ]
    meta_tbl = Table(meta_data,colWidths=[W*0.30,W*0.30,W*0.20,W*0.20])
    meta_tbl.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,-1),C_PANEL),("BOX",(0,0),(-1,-1),0.5,C_BORDER),
        ("INNERGRID",(0,0),(-1,-1),0.3,C_BORDER),("TOPPADDING",(0,0),(-1,-1),6),
        ("BOTTOMPADDING",(0,0),(-1,-1),6),("LEFTPADDING",(0,0),(-1,-1),8),
    ]))
    story += [meta_tbl, Spacer(1,10)]

    story.append(Paragraph("// Executive Summary", S["section"]))
    sv = lambda txt,col: Paragraph(txt,ParagraphStyle("_sv",fontName="Helvetica-Bold",fontSize=22,textColor=col,alignment=TA_CENTER,leading=26))
    sl = lambda txt: Paragraph(txt,S["meta_label"])
    stat_data = [
        [sv(str(vuln_count),C_RED),sv(str(warn_count),C_AMBER),sv(str(ok_count),C_GREEN),sv(str(err_count),C_GREY)],
        [sl("High / Vulnerable"),sl("Medium / Warning"),sl("Checks Completed"),sl("Errors / Timeouts")],
    ]
    stat_tbl = Table(stat_data,colWidths=[W/4]*4)
    stat_tbl.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(0,1),colors.HexColor("#1a0a0d")),("BACKGROUND",(1,0),(1,1),colors.HexColor("#1a160a")),
        ("BACKGROUND",(2,0),(2,1),colors.HexColor("#0a1a0a")),("BACKGROUND",(3,0),(3,1),colors.HexColor("#111111")),
        ("BOX",(0,0),(0,-1),1,C_RED),("BOX",(1,0),(1,-1),1,C_AMBER),
        ("BOX",(2,0),(2,-1),1,C_GREEN),("BOX",(3,0),(3,-1),1,C_GREY),
        ("ALIGN",(0,0),(-1,-1),"CENTER"),("TOPPADDING",(0,0),(-1,-1),10),("BOTTOMPADDING",(0,0),(-1,-1),8),
    ]))
    story += [stat_tbl, Spacer(1,10)]

    analyst_text = (f"Automated security assessment of <b>{target}</b> on {scan_time}. "
        f"<b>{len(results)}</b> checks executed across port enumeration, SSL/TLS, HTTP headers, CMS detection, and network services. "
        f"<b>HIGH</b> items require immediate attention; <b>MEDIUM</b> items represent best-practice gaps. "
        f"Only test systems you own or have explicit written authorization to test.")
    note_style = ParagraphStyle("an",fontName="Helvetica",fontSize=8.5,textColor=C_TEXT,leading=13,
        backColor=C_PANEL,borderPad=8,borderColor=C_BORDER,borderWidth=0.5,leftIndent=8,rightIndent=8)
    story += [Paragraph(analyst_text,note_style), Spacer(1,12)]

    story.append(Paragraph("// Detailed Findings with Threat Intelligence", S["section"]))
    cats = {}
    for r in results: cats.setdefault(r.get("category","Other"),[]).append(r)

    for cat,items in cats.items():
        story.append(Paragraph(f"Category: {cat}",ParagraphStyle("ch",fontName="Helvetica-Bold",fontSize=9,
            textColor=C_AMBER,spaceBefore=8,spaceAfter=4,leading=11)))
        for r in items:
            sev,sev_color = _severity(r)
            status = r.get("status","unknown")
            s_color = {"completed":C_GREEN,"error":C_RED,"timeout":C_AMBER}.get(status,C_GREY)
            safe_out = (r.get("output","")[:1500].replace("&","&amp;").replace("<","&lt;").replace(">","&gt;"))
            intel = get_threat_intel(r.get("tool",""))

            hdr = Table([[
                Paragraph(r.get("tool","").replace("_"," ").upper(),S["tool_name"]),
                Paragraph(r.get("description",""),S["tool_desc"]),
                Paragraph(sev,ParagraphStyle("sp",fontName="Helvetica-Bold",fontSize=7.5,textColor=sev_color,alignment=TA_RIGHT,leading=10)),
                Paragraph(status.upper(),ParagraphStyle("sta",fontName="Helvetica-Bold",fontSize=7.5,textColor=s_color,alignment=TA_RIGHT,leading=10)),
            ]],colWidths=[W*0.22,W*0.44,W*0.14,W*0.20])
            hdr.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,-1),colors.HexColor("#161b22")),("BOX",(0,0),(-1,-1),0.4,C_BORDER),
                ("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5),
                ("LEFTPADDING",(0,0),(-1,-1),7),("RIGHTPADDING",(0,0),(-1,-1),7),
                ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
            ]))

            threat_content = [
                [Paragraph("🔍 WHAT IS THIS?",S["threat_hdr"]),Paragraph("⚠️ WHY IT MATTERS",S["threat_hdr"]),Paragraph("🔧 HOW TO FIX",S["threat_hdr"])],
                [Paragraph(intel["what"][:400],S["threat_body"]),Paragraph(intel["why"][:400],S["threat_body"]),Paragraph(intel["fix"][:400],S["threat_body"])],
            ]
            threat_tbl = Table(threat_content,colWidths=[W*0.33,W*0.33,W*0.34])
            threat_tbl.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,-1),colors.HexColor("#0d1117")),
                ("BOX",(0,0),(-1,-1),0.4,C_BORDER),("INNERGRID",(0,0),(-1,-1),0.3,C_BORDER),
                ("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6),
                ("LEFTPADDING",(0,0),(-1,-1),6),("RIGHTPADDING",(0,0),(-1,-1),6),
                ("VALIGN",(0,0),(-1,-1),"TOP"),
            ]))

            body = Table([[Paragraph(safe_out or "(no output)",S["output"])]],colWidths=[W])
            body.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,-1),C_BG),("BOX",(0,0),(-1,-1),0.4,C_BORDER),
                ("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6),
                ("LEFTPADDING",(0,0),(-1,-1),8),("RIGHTPADDING",(0,0),(-1,-1),8),
            ]))
            story.append(KeepTogether([hdr,threat_tbl,body,Spacer(1,8)]))

    story.append(HRFlowable(width="100%",thickness=0.5,color=C_BORDER,spaceBefore=10,spaceAfter=6))
    story.append(Paragraph(f"Generated by MTVS v3.0 · {scan_time} · Target: {target} · All threats include definitions and remediation steps",S["footer"]))
    doc.build(story)
    buf.seek(0)
    return buf


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/')
@login_required
def home():
    return render_template('index.html')

@app.route('/plans', methods=['GET'])
def get_plans():
    return jsonify({k:{"name":v["name"],"price_inr":v["price_inr"],"description":v["description"],
                       "pdf_access":v["pdf_access"],"chat_access":v["chat_access"]} for k,v in PLANS.items()})

@app.route('/create_order', methods=['POST'])
def create_order():
    data = request.get_json()
    plan_key = data.get("plan","medium")
    if plan_key not in PLANS: return jsonify({"error":"Unknown plan"}),400
    plan = PLANS[plan_key]
    if plan["price_paise"]==0: return jsonify({"error":"Free plan does not need payment"}),400
    try:
        resp = req.post("https://api.razorpay.com/v1/orders",
            auth=(RAZORPAY_KEY_ID,RAZORPAY_KEY_SECRET),
            json={"amount":plan["price_paise"],"currency":"INR","receipt":f"mtvs_{plan_key}_{int(time.time())}","notes":{"plan":plan_key}},timeout=10)
        resp.raise_for_status()
        order = resp.json()
        return jsonify({"order_id":order["id"],"amount":order["amount"],"currency":order["currency"],
                        "key_id":RAZORPAY_KEY_ID,"plan":plan_key,"plan_name":plan["name"]})
    except Exception as e:
        return jsonify({"error":str(e)}),500

@app.route('/verify_payment', methods=['POST'])
def verify_payment():
    data = request.get_json()
    order_id=data.get("razorpay_order_id",""); payment_id=data.get("razorpay_payment_id","")
    signature=data.get("razorpay_signature",""); plan_key=data.get("plan","medium")
    expected = hmac.new(RAZORPAY_KEY_SECRET.encode(),f"{order_id}|{payment_id}".encode(),hashlib.sha256).hexdigest()
    if hmac.compare_digest(expected,signature):
        VERIFIED_PAYMENTS[payment_id]=plan_key
        return jsonify({"verified":True,"plan":plan_key})
    return jsonify({"verified":False,"error":"Signature mismatch"}),400

@app.route('/scan', methods=['POST'])
@login_required
def scan():
    data = request.get_json()
    target = data.get('target','').strip()
    selected_tools = data.get('tools',['ping'])
    plan_key = data.get('plan','basic')
    if not target: return jsonify({"error":"No target provided"}),400
    target = url_maker(target)
    allowed = PLAN_TOOL_MAP.get(plan_key)
    if allowed is not None:
        filtered_tools = [t for t in selected_tools if t in allowed]
        blocked = [t for t in selected_tools if t not in allowed]
    else:
        filtered_tools = selected_tools; blocked = []
    results = run_scan(target, filtered_tools)
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    scan_id = save_scan_to_db(target, results, plan_key, scan_time)
    return jsonify({"target":target,"results":results,"blocked":blocked,"plan":plan_key,
                    "scan_id":scan_id,"scan_time":scan_time})

@app.route('/export_pdf', methods=['POST'])
@login_required
def export_pdf():
    data = request.get_json()
    target = data.get('target','unknown')
    results = data.get('results',[])
    scan_time = data.get('scan_time', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    plan_key = data.get('plan','basic')
    plan_name = PLANS.get(plan_key,{}).get("name","Basic")
    try:
        pdf_buf = generate_pdf_report(target, results, scan_time, plan_name)
        filename = f"MTVS_Report_{target.replace('.','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        return send_file(pdf_buf,mimetype='application/pdf',as_attachment=True,download_name=filename)
    except Exception as e:
        return jsonify({"error":f"PDF generation failed: {e}"}),500

@app.route('/chat', methods=['POST'])
@login_required
def chat():
    data = request.get_json()
    messages = data.get('messages',[])
    scan_context = data.get('scan_context','')
    if not messages: return jsonify({"error":"No messages provided"}),400
    if not GROQ_API_KEY: return jsonify({"error":"No Groq API key configured."}),400

    threat_knowledge = "\n\n".join([
        f"TOOL: {k}\nNAME: {v['name']}\nWHAT: {v['what']}\nWHY DANGEROUS: {v['why']}\nFIX: {v['fix']}\nCVE: {v['cve']}"
        for k,v in THREAT_INTEL.items()
    ])

    system_prompt = (
        "You are MTVS-AI, the built-in security assistant for the Multi-Tool Web Vulnerability Scanner. "
        "You have deep knowledge of every tool in the scanner and what it checks for. "
        "Your job is to help users understand their scan results, explain vulnerabilities in plain English, "
        "suggest concrete remediation steps, and answer questions about web security.\n\n"
        "COMPLETE TOOL KNOWLEDGE BASE:\n" + threat_knowledge + "\n\n"
        "When analyzing scan results:\n"
        "1. First identify CRITICAL/HIGH findings that need immediate attention\n"
        "2. Explain in plain English what each vulnerability means\n"
        "3. Give specific, actionable remediation steps for the exact technology found\n"
        "4. Prioritize fixes by severity and ease of implementation\n"
        "5. Mention relevant CVE numbers when applicable\n\n"
        "Always remind users to only scan systems they own or have written authorization to test."
    )
    if scan_context:
        system_prompt += f"\n\nCURRENT SCAN RESULTS:\n{scan_context[:4000]}"

    try:
        resp = req.post("https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization":f"Bearer {GROQ_API_KEY}","Content-Type":"application/json"},
            json={"model":"llama-3.3-70b-versatile","max_tokens":1500,
                  "messages":[{"role":"system","content":system_prompt},*messages]},timeout=30)
        resp.raise_for_status()
        reply = resp.json()["choices"][0]["message"]["content"]
        return jsonify({"reply":reply})
    except req.exceptions.HTTPError as e:
        return jsonify({"error":f"API error: {e.response.status_code}"}),500
    except Exception as e:
        return jsonify({"error":str(e)}),500

@app.route('/history', methods=['GET'])
@login_required
def history():
    limit = request.args.get('limit',50,type=int)
    return jsonify(get_scan_history(limit))

@app.route('/history/<int:scan_id>', methods=['GET'])
@login_required
def history_detail(scan_id):
    detail = get_scan_detail(scan_id)
    if not detail: return jsonify({"error":"Scan not found"}),404
    return jsonify(detail)

@app.route('/history/<int:scan_id>', methods=['DELETE'])
@login_required
def delete_scan(scan_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('DELETE FROM scan_results WHERE scan_id=?',(scan_id,))
    c.execute('DELETE FROM scans WHERE id=?',(scan_id,))
    conn.commit(); conn.close()
    return jsonify({"deleted":True,"id":scan_id})

@app.route('/threat_intel/<tool_key>', methods=['GET'])
def threat_intel_api(tool_key):
    return jsonify(get_threat_intel(tool_key))

@app.route('/tools', methods=['GET'])
def list_tools():
    all_tools = {}
    for key,val in {**PYTHON_SCANS,**SCANS}.items():
        cat = val.get("category","Other")
        if cat not in all_tools: all_tools[cat] = []
        all_tools[cat].append({"key":key,"desc":val["desc"],"threat_intel":get_threat_intel(key)})
    return jsonify(all_tools)

if __name__ == '__main__':
    app.run(debug=True)