class ScoringEngine:
    def calculate_score(self, findings):
        if not findings:
            return "A", 100
            
        counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }
        for f in findings:
            sev = (f.get('severity') or 'INFO').upper()
            if sev not in counts:
                # Map invalid/custom severities to a fallback
                if sev in ("WARNING", "WARN"):
                    sev = "MEDIUM"
                elif sev in ("ERROR", "ERR", "FATAL"):
                    sev = "HIGH"
                else:
                    sev = "LOW"
            counts[sev] = counts.get(sev, 0) + 1
            
        # Weighted penalty
        penalty = (counts['CRITICAL'] * 40) + (counts['HIGH'] * 15) + (counts['MEDIUM'] * 5) + (counts['LOW'] * 1)
        score_val = max(0, 100 - penalty)
        
        if counts['CRITICAL'] >= 3 or score_val < 30:
            grade = "F"
        elif counts['CRITICAL'] >= 1 or counts['HIGH'] >= 5 or score_val < 60:
            grade = "D"
        elif counts['HIGH'] >= 2 or score_val < 80:
            grade = "C"
        elif counts['HIGH'] >= 1 or score_val < 95:
            grade = "B"
        else:
            grade = "A"
            
        return grade, score_val
