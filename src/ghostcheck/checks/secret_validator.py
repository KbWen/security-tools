try:
    import requests
except ImportError:
    requests = None
import logging

logger = logging.getLogger(__name__)

class SecretValidator:
    def __init__(self, enabled=False, proxy=None, ssl_verify=True, timeout=10):
        self.enabled = enabled
        self.proxy = proxy
        self.ssl_verify = ssl_verify
        self.timeout = timeout
        self.proxies = {"http": proxy, "https": proxy} if proxy else None

    def validate(self, finding):
        if not self.enabled or requests is None:
            return None
            
        token = finding.get('context')
        name = finding.get('name', '')
        
        # Example validation for OpenAI
        if "openai" in name.lower() or (token and token.startswith("sk-")):
            return self._validate_openai(token)
            
        return None

    def _validate_openai(self, token):
        try:
            # Simple check against models list
            headers = {"Authorization": f"Bearer {token}"}
            resp = requests.get(
                "https://api.openai.com/v1/models", 
                headers=headers, 
                timeout=self.timeout,
                proxies=self.proxies,
                verify=self.ssl_verify
            )
            if resp.status_code == 200:
                return {"valid": True, "status": "LIVE", "message": "Token is ACTIVE and valid."}
            elif resp.status_code == 401:
                return {"valid": False, "status": "INVALID", "message": "Token is REVOKED or invalid."}
        except requests.RequestException as e:
            logger.debug(f"OpenAI token validation request failed: {e}")
        return {"valid": None, "status": "UNKNOWN", "message": "Could not verify token status."}
