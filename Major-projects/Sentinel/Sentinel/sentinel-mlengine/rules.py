class RuleBasedDetector:
    def __init__(self):
        self.threat_keywords = [
            "exploit", "malware", "union select", 
            "<script>", "eval(", "exec(", 
            "alert(", "../../../"
        ]

    def check(self, payload):
        """
        Returns True if a known threat keyword is found.
        """
        payload_lower = payload.lower()
        for keyword in self.threat_keywords:
            if keyword in payload_lower:
                return True, keyword
        return False, None