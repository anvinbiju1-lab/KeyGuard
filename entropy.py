import math
import re
from typing import List, Dict, Any

def analyze_entropy(password: str) -> Dict[str, Any]:
    """
    Calculates mathematical entropy (bits) based on string length and character pool size.
    Returns pool breakdown, entropy score, strength tier, crack time estimate, and recommendations.
    """
    if not password:
        return {
            "entropy": 0.0,
            "length": 0,
            "pool_size": 0,
            "pool_breakdown": {
                "lowercase": False,
                "uppercase": False,
                "numbers": False,
                "symbols": False
            },
            "strength": "Weak",
            "crack_time_display": "Instant",
            "recommendations": ["Enter a password to begin audit."]
        }

    length = len(password)
    
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digits = bool(re.search(r'\d', password))
    has_symbols = bool(re.search(r'[^a-zA-Z0-9]', password))

    pool_size = 0
    if has_lower:
        pool_size += 26
    if has_upper:
        pool_size += 26
    if has_digits:
        pool_size += 10
    if has_symbols:
        pool_size += 32

    # Calculate entropy E = L * log2(R)
    if pool_size > 0:
        entropy = round(length * math.log2(pool_size), 1)
    else:
        entropy = 0.0

    # Determine Strength Classification
    if entropy < 35:
        strength = "Weak"
    elif entropy < 60:
        strength = "Moderate"
    elif entropy < 90:
        strength = "Strong"
    else:
        strength = "Enterprise"

    crack_time_display = estimate_crack_time(entropy)
    recommendations = generate_recommendations(password, length, has_lower, has_upper, has_digits, has_symbols)

    return {
        "entropy": entropy,
        "length": length,
        "pool_size": pool_size,
        "pool_breakdown": {
            "lowercase": has_lower,
            "uppercase": has_upper,
            "numbers": has_digits,
            "symbols": has_symbols
        },
        "strength": strength,
        "crack_time_display": crack_time_display,
        "recommendations": recommendations
    }

def estimate_crack_time(entropy: float) -> str:
    """
    Estimates offline cracking duration assuming an attacker attempting 10 billion (10^10) guesses/sec.
    """
    if entropy <= 0:
        return "Instant"
        
    combinations = 2 ** entropy
    avg_guesses = combinations / 2.0
    guesses_per_sec = 10_000_000_000.0  # 10 Billion/sec (modern GPU array)

    seconds = avg_guesses / guesses_per_sec

    if seconds < 1:
        return "Instant (< 1 second)"
    elif seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        return f"{int(seconds // 60)} minutes"
    elif seconds < 86400:
        return f"{int(seconds // 3600)} hours"
    elif seconds < 31536000:
        return f"{int(seconds // 86400)} days"
    elif seconds < 31536000 * 100:
        years = int(seconds // 31536000)
        return f"{years:,} years"
    elif seconds < 31536000 * 1_000_000:
        k_years = int(seconds // (31536000 * 1000))
        return f"{k_years:,} thousand years"
    else:
        m_years = int(seconds // (31536000 * 1_000_000))
        return f"{m_years:,} million years"

def generate_recommendations(
    password: str,
    length: int,
    has_lower: bool,
    has_upper: bool,
    has_digits: bool,
    has_symbols: bool
) -> List[str]:
    recommendations = []

    if length < 12:
        recommendations.append("Increase length to at least 12–16 characters to build resilience against brute-force attacks.")
    
    if not has_upper:
        recommendations.append("Incorporate uppercase letters (A-Z) to expand character pool size.")
    
    if not has_lower:
        recommendations.append("Incorporate lowercase letters (a-z) to improve character variety.")

    if not has_digits:
        recommendations.append("Add numeric digits (0-9) to expand the pool size by 10 characters.")

    if not has_symbols:
        recommendations.append("Include special symbols (!@#$) to significantly increase character entropy.")

    if re.search(r'(.)\1{2,}', password):
        recommendations.append("Avoid repeating the same character 3 or more times consecutively.")

    lower_pwd = password.lower()
    sequences = ["12345", "abcde", "qwerty", "password", "admin", "welcome", "12345678"]
    for seq in sequences:
        if seq in lower_pwd:
            recommendations.append(f"Remove common sequence or dictionary pattern ('{seq}').")
            break

    if len(recommendations) == 0:
        recommendations.append("Excellent password composition. Meets top enterprise security standards.")

    return recommendations
