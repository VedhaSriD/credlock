"""
Calculate Shannon entropy to detect real secrets vs noise.

Real secrets (API keys, tokens):
  - High entropy: 5.0-7.0
  - Random characters
  
False positives (messages, labels):
  - Low entropy: 2.0-4.0
  - Natural language or predictable
"""

from math import log2
from collections import Counter


def calculate_entropy(s: str) -> float:
    """
    Calculate Shannon entropy of a string.
    
    Measures randomness/disorder:
    - 0 = all same character
    - 7+ = very random (typical API key)
    - 3-4 = natural language or weak password
    
    Args:
        s: String to measure
        
    Returns:
        Entropy value (float)
    """
    if not s or len(s) < 1:
        return 0.0
    
    # Count character frequencies
    counts = Counter(s)
    
    # Calculate Shannon entropy: -Σ(p_i * log2(p_i))
    entropy = 0.0
    length = len(s)
    
    for count in counts.values():
        probability = count / length
        entropy -= probability * log2(probability)
    
    return entropy


def is_high_entropy(s: str, threshold: float = 3.5) -> bool:
    """
    Check if string has high entropy (likely a real secret).
    
    Args:
        s: String to check
        threshold: Minimum entropy value (default 3.5)
        
    Returns:
        True if entropy > threshold, False otherwise
    """
    if not s:
        return False
    
    entropy = calculate_entropy(s)
    return entropy > threshold


# CORRECTED ENTROPY THRESHOLDS - MATCH patterns.py!
# HIGH thresholds filter npm hashes, UUIDs, and false positives
ENTROPY_THRESHOLDS = {
    # AWS
    "aws_key": 3.5,
    "aws_access_key": 3.5,
    "aws_secret_key": 3.5,
    "aws_config": 3.0,
    "aws_session_token": 3.5,
    "aws_mfa_device": 2.0,
    
    # GitHub
    "github_token": 3.5,
    "github_oauth": 3.5,
    "github_app_token": 3.5,
    
    # Stripe
    "stripe_key_live": 3.5,
    "stripe_key_test": 3.0,
    "stripe_restricted_key": 3.5,
    
    # Private Keys
    "private_key_rsa": 3.0,
    "private_key_openssh": 3.0,
    "private_key_ec": 3.0,
    "private_key_pgp": 3.0,
    "private_key_pem": 3.0,
    
    # Database URLs
    "postgres_url": 2.5,
    "mysql_url": 2.5,
    "mongodb_url": 2.5,
    "mongodb_connection": 2.5,
    "database_url": 2.5,
    
    # API Keys
    "api_key_generic": 3.2,
    "sendgrid_key": 3.5,
    "firebase_key": 3.0,
    "generic_api_key": 3.5,
    "generic_secret_env": 2.8,
    "openai_api_key": 3.5,
    "huggingface_token": 3.5,
    "pinecone_api_key": 3.5,
    
    # JWT & OAuth
    "jwt_token": 3.5,
    "oauth_token": 3.0,
    
    # Slack
    "slack_token": 3.5,
    "slack_bot_token": 3.5,
    "slack_webhook": 2.5,
    
    # Passwords & Auth
    "password_assignment": 3.5,  # FILTERS: "Enter your password"
    "env_secret": 2.5,
    "bearer_token": 2.5,
    "basic_auth": 2.5,
    
    # Communication & Services
    "heroku_key": 4.2,  # FILTERS: UUIDs in npm
    "heroku_api_key": 4.2,  # FILTERS: UUIDs in npm
    "twilio_api_key": 3.5,
    "twilio_auth_token": 4.0,  # FILTERS: random strings
    "twilio_account_sid": 3.5,
    "mailchimp_key": 3.5,
    "discord_webhook": 2.5,
    "telegram_bot_token": 3.0,
    
    # Code Repos
    "npm_token": 3.5,
    "docker_hub_token": 3.5,
    "gitlab_personal_token": 3.0,
    "bitbucket_token": 3.5,
    
    # Work Tools
    "jira_api_token": 3.0,
    "jenkins_api_token": 3.0,
    
    # Cloud Services
    "azure_connection_string": 2.0,
    "azure_key": 4.5,  # FILTERS: npm integrity hashes (sha512 base64)
    "gcp_service_account": 2.0,
    
    # Assignment Patterns
    "api_secret_assignment": 3.0,
    "certificate_key": 2.0,
    
    # Vault & Secrets
    "vault_token": 3.5,
    
    # Data Monitoring
    "datadog_key": 4.5,  # FILTERS: hex strings like npm integrity
}


def is_likely_secret(matched_string: str, pattern_type: str) -> bool:
    """
    Determine if a match is likely a real secret based on entropy.
    
    Args:
        matched_string: The string that matched the pattern
        pattern_type: Type of pattern (aws_key, github_token, etc.)
        
    Returns:
        True if likely a real secret, False if likely false positive
    """
    if not matched_string:
        return False
    
    threshold = ENTROPY_THRESHOLDS.get(pattern_type, 3.0)
    return is_high_entropy(matched_string, threshold)


# Test examples (for verification)
if __name__ == "__main__":
    print("Real secrets:")
    print(f"  AWS key: {calculate_entropy('AKIA7JKQWL2MXKBP9QVW'):.2f}")
    print(f"  API key: {calculate_entropy('sk_live_51HqLkFBPZmKL2jQ9k3m4n5p6q7r8s9t0u1v2w3x4y'):.2f}")
    
    print("\nFalse positives (should be <4.5 for azure_key):")
    print(f"  npm hash: {calculate_entropy('sha512-J1yXrIlNDZVzE3ada310xeAw7nH8yCAyL'):.2f}")
    print(f"  UUID: {calculate_entropy('11ecafe2-56c6-41d6-8e9c-b57022b20152'):.2f}")
    print(f"  Message: {calculate_entropy('Enter your password'):.2f}")