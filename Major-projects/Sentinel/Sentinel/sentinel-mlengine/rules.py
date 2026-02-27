"""
Sentinel ML Engine - Rule-Based Filter (Layer 1)
Fast keyword-based detection for known attack patterns
"""

import re
import config


class RuleBasedFilter:
    """
    Layer 1: Fast rule-based detection
    Instantly blocks known malicious patterns
    ~1ms response time
    """
    
    def __init__(self):
        self.blacklist = config.BLACKLIST_KEYWORDS
        self.attack_patterns = config.ATTACK_PATTERNS
        self.stats = {
            'total_checks': 0,
            'blocked_count': 0,
        }
    
    def check(self, payload):
        """
        Check payload against blacklist rules
        
        Returns:
            dict: {
                'is_malicious': bool,
                'confidence': float (0-1),
                'matched_rule': str or None,
                'attack_type': str or None
            }
        """
        self.stats['total_checks'] += 1
        
        payload_lower = payload.lower()
        
        # Check blacklist keywords
        for keyword in self.blacklist:
            if keyword.lower() in payload_lower:
                self.stats['blocked_count'] += 1
                return {
                    'is_malicious': True,
                    'confidence': config.RULE_BASED_CONFIDENCE,
                    'matched_rule': keyword,
                    'attack_type': self._classify_attack_type(keyword),
                    'layer': 'Rule-Based (Layer 1)'
                }
        
        # If no exact match, not detected by rules
        return {
            'is_malicious': False,
            'confidence': 0.0,
            'matched_rule': None,
            'attack_type': None,
            'layer': 'Rule-Based (Layer 1)'
        }
    
    def _classify_attack_type(self, keyword):
        """Classify attack type based on matched keyword"""
        keyword_lower = keyword.lower()
        
        if any(sql in keyword_lower for sql in ['select', 'union', 'drop', 'insert', 'exec']):
            return 'SQL Injection'
        elif any(xss in keyword_lower for xss in ['script', 'javascript', 'onerror', 'onload']):
            return 'Cross-Site Scripting (XSS)'
        elif any(cmd in keyword_lower for cmd in ['cat', 'bash', 'sh', 'wget', 'curl']):
            return 'Command Injection'
        elif '../' in keyword_lower or '..\\' in keyword_lower:
            return 'Path Traversal'
        else:
            return 'Unknown'
    
    def map_to_mitre(self, payload):
        """
        Map payload to MITRE ATT&CK techniques
        
        Returns:
            list: List of technique IDs (e.g., ['T1059', 'T1190'])
        """
        techniques = []
        
        for technique_id, pattern in self.attack_patterns.items():
            if re.search(pattern, payload, re.IGNORECASE):
                techniques.append(technique_id)
        
        return techniques
    
    def get_stats(self):
        """Return statistics"""
        return {
            'total_checks': self.stats['total_checks'],
            'blocked_count': self.stats['blocked_count'],
            'block_rate': self.stats['blocked_count'] / self.stats['total_checks'] 
                         if self.stats['total_checks'] > 0 else 0.0
        }


# Example usage
if __name__ == "__main__":
    filter = RuleBasedFilter()
    
    test_payloads = [
        "GET /index.html HTTP/1.1",
        "admin' OR '1'='1'--",
        "<script>alert('XSS')</script>",
        "normal search query",
        "; cat /etc/passwd",
    ]
    
    print("="*80)
    print("RULE-BASED FILTER TEST")
    print("="*80)
    
    for payload in test_payloads:
        result = filter.check(payload)
        mitre = filter.map_to_mitre(payload)
        
        print(f"\nPayload: {payload}")
        print(f"Malicious: {result['is_malicious']}")
        if result['is_malicious']:
            print(f"Confidence: {result['confidence']:.2f}")
            print(f"Matched Rule: {result['matched_rule']}")
            print(f"Attack Type: {result['attack_type']}")
        if mitre:
            print(f"MITRE ATT&CK: {mitre}")
    
    print("\n" + "="*80)
    print("STATISTICS:")
    stats = filter.get_stats()
    print(f"Total Checks: {stats['total_checks']}")
    print(f"Blocked: {stats['blocked_count']}")
    print(f"Block Rate: {stats['block_rate']:.1%}")
    print("="*80)
