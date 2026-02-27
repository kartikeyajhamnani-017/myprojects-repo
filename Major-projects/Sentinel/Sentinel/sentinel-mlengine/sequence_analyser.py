"""
Sentinel ML Engine v2.0 - Sequence Analyzer (Layer 3)
Detects multi-step attack campaigns by tracking IP behavior over time
"""

import time
from collections import deque
import redis
import json
import config


class SequenceAnalyzer:
    """
    Layer 3: Sequential attack pattern detection
    Tracks attacker behavior over time to identify campaigns
    """
    
    def __init__(self, redis_client=None):
        """
        Initialize with Redis connection for distributed state
        If redis_client is None, falls back to in-memory storage
        """
        self.redis_client = redis_client
        
        # Fallback to in-memory storage if Redis unavailable
        if self.redis_client is None:
            self.in_memory_storage = {}
            print("[WARNING] Redis not available. Using in-memory storage (not distributed)")
        else:
            self.in_memory_storage = None
    
    def track_payload(self, ip_address, payload, timestamp=None):
        """
        Track a payload for an IP address
        Maintains sliding window of recent payloads
        """
        if timestamp is None:
            timestamp = time.time()
        
        # Get existing window
        window = self._get_window(ip_address)
        
        # Add new payload
        payload_entry = {
            'payload': payload,
            'timestamp': timestamp,
            'length': len(payload),
        }
        
        window.append(payload_entry)
        
        # Store updated window
        self._set_window(ip_address, window)
    
    def analyze_sequence(self, ip_address):
        """
        Analyze attack sequence for an IP
        
        Returns:
            dict: Sequence features for ML
        """
        window = self._get_window(ip_address)
        
        if len(window) < 2:
            # Not enough data for sequence analysis
            return {
                'seq_payload_count': len(window),
                'seq_escalation_detected': 0,
                'seq_recon_to_exploit': 0,
                'seq_complexity_increase': 0,
                'seq_attack_velocity': 0.0,
                'seq_time_span': 0.0,
            }
        
        # Extract features
        features = {
            'seq_payload_count': len(window),
            'seq_escalation_detected': self._detect_escalation(window),
            'seq_recon_to_exploit': self._detect_recon_to_exploit(window),
            'seq_complexity_increase': self._measure_complexity_trend(window),
            'seq_attack_velocity': self._calculate_velocity(window),
            'seq_time_span': self._calculate_time_span(window),
        }
        
        return features
    
    def _detect_escalation(self, window):
        """Detect privilege escalation pattern"""
        payloads = [entry['payload'].lower() for entry in window]
        
        # Check if commands progress from info gathering to privilege escalation
        early_recon = any(
            keyword in payloads[0] 
            for keyword in ['whoami', 'id', 'uname', 'hostname']
        )
        
        later_privesc = any(
            keyword in payload 
            for payload in payloads[-3:] 
            for keyword in ['sudo', 'su -', 'passwd', '/etc/shadow']
        )
        
        return 1 if (early_recon and later_privesc) else 0
    
    def _detect_recon_to_exploit(self, window):
        """
        Detect pattern: Reconnaissance → Exploitation
        Example: SELECT 1 → UNION SELECT password FROM users
        """
        if len(window) < 3:
            return 0
        
        early_payloads = [entry['payload'].lower() for entry in window[:3]]
        later_payloads = [entry['payload'].lower() for entry in window[-3:]]
        
        # Check for recon keywords in early payloads
        recon_keywords = ['select 1', 'version()', 'database()', '@@version']
        early_is_recon = any(
            keyword in payload 
            for payload in early_payloads 
            for keyword in recon_keywords
        )
        
        # Check for exploit keywords in later payloads
        exploit_keywords = ['union', 'drop', 'insert', 'delete', 'update']
        later_is_exploit = any(
            keyword in payload 
            for payload in later_payloads 
            for keyword in exploit_keywords
        )
        
        return 1 if (early_is_recon and later_is_exploit) else 0
    
    def _measure_complexity_trend(self, window):
        """
        Measure if payload complexity increases over time
        Returns: 1 if increasing, 0 if stable/decreasing
        """
        if len(window) < 3:
            return 0
        
        # Calculate complexity scores (based on length and special chars)
        complexities = []
        for entry in window:
            payload = entry['payload']
            special_chars = sum(1 for c in payload if not c.isalnum())
            complexity = len(payload) + (special_chars * 2)  # Weight special chars
            complexities.append(complexity)
        
        # Check if trend is increasing
        first_third_avg = sum(complexities[:len(complexities)//3]) / (len(complexities)//3)
        last_third_avg = sum(complexities[-len(complexities)//3:]) / (len(complexities)//3)
        
        return 1 if last_third_avg > first_third_avg * 1.5 else 0
    
    def _calculate_velocity(self, window):
        """
        Calculate attack velocity (payloads per minute)
        High velocity = automated attack
        """
        if len(window) < 2:
            return 0.0
        
        time_span = self._calculate_time_span(window)
        if time_span == 0:
            return 0.0
        
        # Payloads per minute
        velocity = (len(window) / time_span) * 60
        return velocity
    
    def _calculate_time_span(self, window):
        """Calculate time span of window in seconds"""
        if len(window) < 2:
            return 0.0
        
        first_time = window[0]['timestamp']
        last_time = window[-1]['timestamp']
        
        return last_time - first_time
    
    def _get_window(self, ip_address):
        """Get sliding window for IP (from Redis or memory)"""
        if self.redis_client:
            # Get from Redis
            key = f"window:{ip_address}"
            data = self.redis_client.get(key)
            
            if data:
                window = json.loads(data)
                # Convert to deque with max length
                return deque(window, maxlen=config.SEQUENCE_WINDOW_SIZE)
            else:
                return deque(maxlen=config.SEQUENCE_WINDOW_SIZE)
        else:
            # Get from in-memory storage
            if ip_address not in self.in_memory_storage:
                self.in_memory_storage[ip_address] = deque(maxlen=config.SEQUENCE_WINDOW_SIZE)
            return self.in_memory_storage[ip_address]
    
    def _set_window(self, ip_address, window):
        """Store sliding window for IP (to Redis or memory)"""
        if self.redis_client:
            # Store to Redis
            key = f"window:{ip_address}"
            data = json.dumps(list(window))
            self.redis_client.setex(
                key, 
                config.SEQUENCE_TIMEOUT, 
                data
            )
        else:
            # Store to in-memory
            self.in_memory_storage[ip_address] = window
    
    def get_all_tracked_ips(self):
        """Get list of all IPs currently being tracked"""
        if self.redis_client:
            keys = self.redis_client.keys("window:*")
            return [key.replace("window:", "") for key in keys]
        else:
            return list(self.in_memory_storage.keys())
    
    def clear_ip(self, ip_address):
        """Clear tracking data for an IP"""
        if self.redis_client:
            self.redis_client.delete(f"window:{ip_address}")
        else:
            if ip_address in self.in_memory_storage:
                del self.in_memory_storage[ip_address]


# Example usage
if __name__ == "__main__":
    # Try to connect to Redis, fallback to in-memory
    try:
        r = redis.Redis(host=config.REDIS_HOST, port=config.REDIS_PORT, db=config.REDIS_DB)
        r.ping()  # Test connection
        print("[INFO] Connected to Redis")
    except:
        print("[WARNING] Redis not available, using in-memory storage")
        r = None
    
    analyzer = SequenceAnalyzer(redis_client=r)
    
    # Simulate attack sequence
    print("="*80)
    print("SEQUENCE ANALYZER TEST - Simulating SQL Injection Attack")
    print("="*80)
    
    attacker_ip = "192.168.1.100"
    
    # Stage 1: Reconnaissance
    print("\nStage 1: Reconnaissance")
    analyzer.track_payload(attacker_ip, "SELECT 1", timestamp=1000.0)
    analyzer.track_payload(attacker_ip, "SELECT version()", timestamp=1001.0)
    analyzer.track_payload(attacker_ip, "SELECT database()", timestamp=1002.0)
    
    # Stage 2: Exploitation
    print("Stage 2: Exploitation")
    analyzer.track_payload(attacker_ip, "' UNION SELECT password FROM users--", timestamp=1010.0)
    analyzer.track_payload(attacker_ip, "' UNION SELECT * FROM admin--", timestamp=1015.0)
    analyzer.track_payload(attacker_ip, "'; DROP TABLE users--", timestamp=1020.0)
    
    # Analyze
    print("\nAnalyzing attack sequence...")
    features = analyzer.analyze_sequence(attacker_ip)
    
    print("\nSequence Features:")
    for key, value in features.items():
        print(f"  {key}: {value}")
    
    print("\n" + "="*80)
    print("INTERPRETATION:")
    if features['seq_recon_to_exploit'] == 1:
        print("✓ Detected: Reconnaissance → Exploitation pattern")
    if features['seq_complexity_increase'] == 1:
        print("✓ Detected: Increasing payload complexity")
    if features['seq_attack_velocity'] > 10:
        print(f"✓ Detected: High attack velocity ({features['seq_attack_velocity']:.1f} payloads/min)")
    print("="*80)
    
    # Test with normal user
    print("\n" + "="*80)
    print("NORMAL USER TEST")
    print("="*80)
    
    normal_ip = "192.168.1.50"
    analyzer.track_payload(normal_ip, "GET /index.html", timestamp=2000.0)
    analyzer.track_payload(normal_ip, "GET /about.html", timestamp=2030.0)
    analyzer.track_payload(normal_ip, "GET /contact.html", timestamp=2060.0)
    
    normal_features = analyzer.analyze_sequence(normal_ip)
    print("\nNormal User Features:")
    for key, value in normal_features.items():
        print(f"  {key}: {value}")
    
    print("\n" + "="*80)
    print(f"Tracked IPs: {analyzer.get_all_tracked_ips()}")
    print("="*80)
