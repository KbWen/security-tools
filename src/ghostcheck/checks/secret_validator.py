try:
    import requests
except ImportError:
    requests = None
import logging
import re

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
            
        token = finding.get('_raw_value')
        if not isinstance(token, str) or not token.strip() or not token.isascii() or any(c in token for c in ('\n', '\r', ' ', '\t')):
            return None

        name = str(finding.get('name') or finding.get('pattern_name') or '').lower()

        non_openai_prefixes = ("sk-ant-", "sk-or-", "sk-lf-", "sk_live_", "sk_test_")
        non_openai_providers = (
            "anthropic", "stripe", "clerk", "openrouter",
            "langfuse", "deepseek", "qwen", "moonshot", "dashscope",
        )

        if token.startswith(non_openai_prefixes):
            return None
        if any(provider in name for provider in non_openai_providers):
            return None

        is_modern_openai = bool(re.match(r'^sk-(?:proj|svcacct|admin|None)-[A-Za-z0-9_-]{10,}$', token))
        is_legacy_openai = bool(re.match(r'^sk-[A-Za-z0-9]{20,}$', token))
        is_named_openai = "openai" in name and token.startswith("sk-")

        if is_modern_openai or is_legacy_openai or is_named_openai:
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
        except (requests.RequestException, UnicodeError) as e:
            logger.debug(f"OpenAI token validation request failed: {e}")
        return {"valid": None, "status": "UNKNOWN", "message": "Could not verify token status."}
