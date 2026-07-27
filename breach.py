import hashlib
import httpx
from typing import Dict, Any, Tuple

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"

async def check_breach(password: str) -> Dict[str, Any]:
    """
    Evaluates password exposure against HaveIBeenPwned via k-Anonymity API.
    Sends only the 5-character SHA-1 prefix over HTTPS to guarantee Zero-Knowledge privacy.
    Returns breach status, breach count, and hash verification metadata.
    """
    if not password:
        return {
            "is_breached": False,
            "breach_count": 0,
            "sha1_prefix": "",
            "sha1_suffix_masked": "",
            "status": "idle",
            "message": "No password provided"
        }

    # Generate SHA-1 uppercase digest
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            headers = {
                "User-Agent": "KeyGuard-ZeroKnowledge-Auditor/1.0",
                "Add-Padding": "true"  # HIBP padding against response-size side-channel attacks
            }
            response = await client.get(HIBP_RANGE_URL.format(prefix=prefix), headers=headers)
            
            if response.status_code != 200:
                return {
                    "is_breached": False,
                    "breach_count": 0,
                    "sha1_prefix": prefix,
                    "sha1_suffix_masked": f"{suffix[:4]}...{suffix[-4:]}",
                    "status": "error",
                    "message": f"HIBP API returned status {response.status_code}"
                }

            # Response consists of lines formatted as SUFFIX:COUNT
            lines = response.text.splitlines()
            breach_count = 0
            is_breached = False

            for line in lines:
                if not line:
                    continue
                parts = line.split(':')
                if len(parts) == 2:
                    resp_suffix, count_str = parts[0].strip(), parts[1].strip()
                    if resp_suffix == suffix:
                        is_breached = True
                        breach_count = int(count_str)
                        break

            return {
                "is_breached": is_breached,
                "breach_count": breach_count,
                "sha1_prefix": prefix,
                "sha1_suffix_masked": f"{suffix[:4]}...{suffix[-4:]}",
                "status": "success",
                "message": "Audited via HIBP k-Anonymity"
            }

    except Exception as e:
        # Fallback gracefully if network / API is unreachable
        return {
            "is_breached": False,
            "breach_count": 0,
            "sha1_prefix": prefix,
            "sha1_suffix_masked": f"{suffix[:4]}...{suffix[-4:]}",
            "status": "unreachable",
            "message": f"Could not reach breach database: {str(e)}"
        }
