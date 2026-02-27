"""
Sentinel ML Engine v2.0 - Configuration
Central configuration for all components
"""

# Redis Configuration (for sequence tracking)
REDIS_HOST = 'localhost'
REDIS_PORT = 6379
REDIS_DB = 0

# Feature Extraction Settings
NGRAM_RANGE = (2, 5)  # Character n-grams from 2 to 5
MAX_NGRAM_FEATURES = 50  # Limit n-gram features

# ML Model Settings
ISOLATION_FOREST_CONTAMINATION = 0.1  # Expected % of anomalies (10%)
ISOLATION_FOREST_N_ESTIMATORS = 100
RANDOM_STATE = 42

# Sequence Analysis Settings
SEQUENCE_WINDOW_SIZE = 10  # Track last 10 payloads per IP
SEQUENCE_TIMEOUT = 3600  # Forget IP after 1 hour of inactivity

# Detection Thresholds
ANOMALY_SCORE_THRESHOLD = 0.6  # 0-1, higher = stricter
RULE_BASED_CONFIDENCE = 1.0  # Rules give 100% confidence
ML_ANOMALY_CONFIDENCE = 0.8  # ML anomalies get 80% confidence

# Known Bad Patterns (Rule-Based Filter)
BLACKLIST_KEYWORDS = [
    # SQL Injection
    "' OR '1'='1",
    "' OR 1=1--",
    "UNION SELECT",
    "DROP TABLE",
    "exec(",
    "xp_cmdshell",
    
    # XSS
    "<script>",
    "javascript:",
    "onerror=",
    "onload=",
    
    # Command Injection
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "&& cat /etc/passwd",
    
    # Path Traversal
    "../../../etc/passwd",
    "..\\..\\..\\windows",
    
    # Other
    "/bin/bash",
    "/bin/sh",
    "wget http",
    "curl http",
]

# Dangerous N-grams (will be detected in feature extraction)
DANGEROUS_NGRAMS = [
    "' OR",
    "' AND",
    "<script",
    "javascript:",
    "../",
    "union select",
    "drop table",
    "exec(",
    "%00",  # Null byte
    "cmd.exe",
    "/bin/sh",
]

# MITRE ATT&CK Mapping
ATTACK_PATTERNS = {
    'T1059': r'(bash|sh|cmd\.exe|powershell|exec\()',  # Command execution
    'T1082': r'(whoami|uname|hostname|systeminfo)',     # System info discovery
    'T1083': r'(ls|dir|find)',                          # File discovery
    'T1003': r'(/etc/passwd|/etc/shadow|SAM)',          # Credential dumping
    'T1190': r'(UNION|SELECT.*FROM|\'.*OR.*=)',         # Exploit public app (SQLi)
    'T1057': r'(ps aux|tasklist|netstat)',              # Process discovery
    'T1027': r'(%[0-9a-fA-F]{2}|base64|\\x[0-9a-f]{2})', # Obfuscated files/info
}

# Logging
LOG_LEVEL = 'INFO'
LOG_FILE = 'sentinel_ml.log'

# Model Persistence
MODEL_PATH = 'models/isolation_forest.pkl'
SCALER_PATH = 'models/feature_scaler.pkl'
