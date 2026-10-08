"""
Secret detection patterns with confidence levels and entropy requirements.

Each pattern includes:
- name: Pattern name
- pattern: Regex pattern
- confidence: HIGH/MEDIUM/LOW
- entropy_threshold: Minimum entropy (4.5+ filters npm hashes)
- exclude_files: Files to skip
"""

from typing import Dict, List
from dataclasses import dataclass


@dataclass
class SecretPattern:
    """A secret detection pattern with metadata."""
    name: str
    pattern: str
    confidence: str
    entropy_threshold: float
    exclude_files: List[str]


# All detection patterns (50+)
PATTERNS = {
    # AWS Credentials - HIGH confidence
    "aws_access_key": SecretPattern(
        name="aws_access_key",
        pattern=r"AKIA[0-9A-Z]{16}",
        confidence="HIGH",
        entropy_threshold=3.5,
        exclude_files=[]
    ),
    
    "aws_secret_key": SecretPattern(
        name="aws_secret_key",
        pattern=r"aws_secret_access_key\s*=\s*['\"]([a-zA-Z0-9+/]{40})['\"]",
        confidence="HIGH",
        entropy_threshold=3.5,
        exclude_files=[]
    ),
    
    "aws_config": SecretPattern(
        name="aws_config",
        pattern=r"\[aws_access_key_id\]|aws_secret_access_key",
        confidence="MEDIUM",
        entropy_threshold=3.0,
        exclude_files=[]
    ),
    
    "aws_session_token": SecretPattern(
        name="aws_session_token",
        pattern=r"ASIA[0-9A-Z]{16}",
        confidence="HIGH",
        entropy_threshold=3.5,
        exclude_files=[]
    ),
    
    # GitHub Tokens - HIGH confidence
    "github_token": SecretPattern(
        name="github_token",
        pattern=r"gh[pousr]_[A-Za-z0-9_]{36,255}",
        confidence="HIGH",
        entropy_threshold=3.5,
        exclude_files=[]
    ),
    
    "github_oauth": SecretPattern(
        name="github_oauth",
        pattern=r"ghu_[0-9a-zA-Z]{36}",
        confidence="HIGH",
        entropy_threshold=3.5,
        exclude_files=[]
    ),
    
    "github_app_token": SecretPattern(
        name="github_app_token",
        pattern=r"ghu_[0-9a-zA-Z]{36}",
        confidence="HIGH",
        entropy_threshold=3.5,
        exclude_files=[]
    ),
    
    # Stripe Keys - HIGH confidence
    "stripe_key_live": SecretPattern(
        name="stripe_key_live",
        pattern=r"sk_live_[a-zA-Z0-9]{24,}",
        confidence="HIGH",
        entropy_threshold=3.5,
        exclude_files=[]
    ),
    
    "stripe_key_test": SecretPattern(
        name="stripe_key_test",
        pattern=r"sk_test_[a-zA-Z0-9]{24,}",
        confidence="MEDIUM",
        entropy_threshold=3.0,
        exclude_files=[]
    ),
    
    "stripe_restricted_key": SecretPattern(
        name="stripe_restricted_key",
        pattern=r"rk_(live|test)_[a-zA-Z0-9]{24,}",
        confidence="HIGH",
        entropy_threshold=3.5,
        exclude_files=[]
    ),
    
    # Private Keys - HIGH confidence
    "private_key_rsa": SecretPattern(
        name="private_key_rsa",
        pattern=r"-----BEGIN RSA PRIVATE KEY-----",
        confidence="HIGH",
        entropy_threshold=3.0,
        exclude_files=[]
    ),
    
    "private_key_openssh": SecretPattern(
        name="private_key_openssh",
        pattern=r"-----BEGIN OPENSSH PRIVATE KEY-----",
        confidence="HIGH",
        entropy_threshold=3.0,
        exclude_files=[]
    ),
    
    "private_key_ec": SecretPattern(
        name="private_key_ec",
        pattern=r"-----BEGIN EC PRIVATE KEY-----",
        confidence="HIGH",
        entropy_threshold=3.0,
        exclude_files=[]
    ),
    
    "private_key_pgp": SecretPattern(
        name="private_key_pgp",
        pattern=r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        confidence="HIGH",
        entropy_threshold=3.0,
        exclude_files=[]
    ),
    
    "private_key_pem": SecretPattern(
        name="private_key_pem",
        pattern=r"-----BEGIN PRIVATE KEY-----",
        confidence="HIGH",
        entropy_threshold=3.0,
        exclude_files=[]
    ),
    
    # Database URLs - HIGH confidence
    "database_url": SecretPattern(
        name="database_url",
        pattern=r"(postgres|mysql|mongodb)://[a-zA-Z0-9_]+:[a-zA-Z0-9_!@#$%^&*]{6,}@",
        confidence="HIGH",
        entropy_threshold=2.5,
        exclude_files=[]
    ),
    
    "postgres_url": SecretPattern(
        name="postgres_url",
        pattern=r"postgres://[a-zA-Z0-9_]+:[a-zA-Z0-9_!@#$%^&*]{6,}@[^/\s]+",
        confidence="HIGH",
        entropy_threshold=2.5,
        exclude_files=[]
    ),
    
    "mysql_url": SecretPattern(
        name="mysql_url",
        pattern=r"mysql://[a-zA-Z0-9_]+:[a-zA-Z0-9_!@#$%^&*]{6,}@[^/\s]+",
        confidence="HIGH",
        entropy_threshold=2.5,
        exclude_files=[]
    ),
    
    "mongodb_connection": SecretPattern(
        name="mongodb_connection",
        pattern=r"mongodb://[a-zA-Z0-9_]+:[a-zA-Z0-9_!@#$%^&*]{6,}@",
        confidence="HIGH",
        entropy_threshold=2.5,
        exclude_files=[]
    ),
    
    "mongodb_url": SecretPattern(
        name="mongodb_url",
        pattern=r"mongodb://[a-zA-Z0-9_]+:[a-zA-Z0-9_!@#$%^&*]{6,}@",
        confidence="HIGH",
        entropy_threshold=2.5,
        exclude_files=[]
    ),
    
    # API Keys - MEDIUM confidence
    "api_key_generic": SecretPattern(
        name="api_key_generic",
        pattern=r"api[_-]?key\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]",
        confidence="MEDIUM",
        entropy_threshold=3.2,
        exclude_files=[]
    ),
    
    "sendgrid_key": SecretPattern(
        name="sendgrid_key",
        pattern=r"SG\.[a-zA-Z0-9_\-]{20,}",
        confidence="HIGH",
        entropy_threshold=3.5,
        exclude_files=[]
    ),
    
    "firebase_key": SecretPattern(
        name="firebase_key",
        pattern=r"AAAA[A-Za-z0-9_-]{7,}",
        confidence="MEDIUM",
        entropy_threshold=3.0,
        exclude_files=[]
    ),
    
    # JWT Tokens - MEDIUM confidence
    "jwt_token": SecretPattern(
        name="jwt_token",
        pattern=r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        confidence="MEDIUM",
        entropy_threshold=3.5,
        exclude_files=[]
    ),
    
    # Slack - HIGH confidence
    "slack_token": SecretPattern(
        name="slack_token",
        pattern=r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9_\-]{20,}",
        confidence="HIGH",
        entropy_threshold=3.5,
        exclude_files=[]
    ),
    
    "slack_bot_token": SecretPattern(
        name="slack_bot_token",
        pattern=r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{20,}",
        confidence="HIGH",
        entropy_threshold=3.5,
        exclude_files=[]
    ),
    
    "slack_webhook": SecretPattern(
        name="slack_webhook",
        pattern=r"https://hooks\.slack\.com/services/[a-zA-Z0-9/_-]+",
        confidence="HIGH",
        entropy_threshold=2.5,
        exclude_files=[]
    ),
    
    # Passwords - MEDIUM confidence
    "password_assignment": SecretPattern(
        name="password_assignment",
        pattern=r"['\"]?password['\"]?\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
        confidence="MEDIUM",
        entropy_threshold=3.5,  # RAISED to filter messages like "Enter your password"
        exclude_files=[]
    ),
    
    # OAuth Tokens - MEDIUM confidence
    "oauth_token": SecretPattern(
        name="oauth_token",
        pattern=r"oauth[_-]?token\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]",
        confidence="MEDIUM",
        entropy_threshold=3.0,
        exclude_files=[]
    ),
    
    # Env secret in code - LOW confidence
    "env_secret": SecretPattern(
        name="env_secret",
        pattern=r"['\"]([a-zA-Z0-9!@#$%^&*\-_]{12,})['\"]",
        confidence="LOW",
        entropy_threshold=2.5,
        exclude_files=["README.md", "README.rst", "CHANGELOG.md"]
    ),
    
    # Additional API Keys
    "heroku_key": SecretPattern(
        name="heroku_key",
        pattern=r"[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}",
        confidence="MEDIUM",
        entropy_threshold=4.2,  # HIGH: filters UUID-like strings in npm
        exclude_files=["package-lock.json", "yarn.lock"]
    ),
    
    "heroku_api_key": SecretPattern(
        name="heroku_api_key",
        pattern=r"[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}",
        confidence="MEDIUM",
        entropy_threshold=4.2,
        exclude_files=["package-lock.json", "yarn.lock"]
    ),
    
    "azure_key": SecretPattern(
        name="azure_key",
        pattern=r"[a-zA-Z0-9+/]{88}==",  # Base64 ~88 chars
        confidence="LOW",
        entropy_threshold=4.5,  # VERY HIGH: filters npm integrity hashes
        exclude_files=["package-lock.json", "yarn.lock", "composer.lock"]
    ),
    
    "vault_token": SecretPattern(
        name="vault_token",
        pattern=r"hvs\.[a-zA-Z0-9_-]{90,}",
        confidence="HIGH",
        entropy_threshold=3.5,
        exclude_files=[]
    ),
    
    "twilio_api_key": SecretPattern(
        name="twilio_api_key",
        pattern=r"AC[a-zA-Z0-9]{32}",
        confidence="HIGH",
        entropy_threshold=3.5,
        exclude_files=[]
    ),
    
    "twilio_auth_token": SecretPattern(
        name="twilio_auth_token",
        pattern=r"[a-zA-Z0-9]{32}",
        confidence="LOW",
        entropy_threshold=4.0,  # HIGH: filters random strings
        exclude_files=[]
    ),
    
    "datadog_key": SecretPattern(
        name="datadog_key",
        pattern=r"[a-f0-9]{32}",
        confidence="LOW",
        entropy_threshold=4.5,  # VERY HIGH: filters hex strings like npm integrity
        exclude_files=["package-lock.json", "yarn.lock"]
    ),
    
    "mailchimp_key": SecretPattern(
        name="mailchimp_key",
        pattern=r"[a-z0-9]{32}-us[0-9]{1,2}",
        confidence="HIGH",
        entropy_threshold=3.5,
        exclude_files=[]
    ),
    
    "npm_token": SecretPattern(
        name="npm_token",
        pattern=r"npm_[a-zA-Z0-9]{36}",
        confidence="HIGH",
        entropy_threshold=3.5,
        exclude_files=[]
    ),
    
    "docker_hub_token": SecretPattern(
        name="docker_hub_token",
        pattern=r"dckr_[a-zA-Z0-9_-]{32,}",
        confidence="HIGH",
        entropy_threshold=3.5,
        exclude_files=[]
    ),
    
    "gitlab_personal_token": SecretPattern(
        name="gitlab_personal_token",
        pattern=r"glpat-[a-zA-Z0-9_-]{20}",
        confidence="HIGH",
        entropy_threshold=3.0,
        exclude_files=[]
    ),
    
    "bitbucket_token": SecretPattern(
        name="bitbucket_token",
        pattern=r"ATBB_[a-zA-Z0-9]{40}",
        confidence="HIGH",
        entropy_threshold=3.5,
        exclude_files=[]
    ),
    
    "jira_api_token": SecretPattern(
        name="jira_api_token",
        pattern=r"jira_token_[a-zA-Z0-9]{32}",
        confidence="HIGH",
        entropy_threshold=3.0,
        exclude_files=[]
    ),
    
    "discord_webhook": SecretPattern(
        name="discord_webhook",
        pattern=r"https://discordapp\.com/api/webhooks/[0-9]{18}/[a-zA-Z0-9_-]{64,68}",
        confidence="HIGH",
        entropy_threshold=2.5,
        exclude_files=[]
    ),
    
    "telegram_bot_token": SecretPattern(
        name="telegram_bot_token",
        pattern=r"[0-9]{9,10}:[a-zA-Z0-9_-]{35,44}",
        confidence="HIGH",
        entropy_threshold=3.0,
        exclude_files=[]
    ),
    
    "aws_mfa_device": SecretPattern(
        name="aws_mfa_device",
        pattern=r"arn:aws:iam::[0-9]{12}:mfa",
        confidence="MEDIUM",
        entropy_threshold=2.0,
        exclude_files=[]
    ),
    
    "azure_connection_string": SecretPattern(
        name="azure_connection_string",
        pattern=r"DefaultEndpointsProtocol=https;.*AccountKey=",
        confidence="HIGH",
        entropy_threshold=2.0,
        exclude_files=[]
    ),
    
    "gcp_service_account": SecretPattern(
        name="gcp_service_account",
        pattern=r"type.*service_account.*private_key",
        confidence="HIGH",
        entropy_threshold=2.0,
        exclude_files=[]
    ),
    
    "api_secret_assignment": SecretPattern(
        name="api_secret_assignment",
        pattern=r"(api_secret|client_secret|consumer_secret)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]",
        confidence="HIGH",
        entropy_threshold=3.0,
        exclude_files=[]
    ),
    
    "bearer_token": SecretPattern(
        name="bearer_token",
        pattern=r"Bearer\s+[a-zA-Z0-9_\-\.]{20,}",
        confidence="MEDIUM",
        entropy_threshold=2.5,
        exclude_files=[]
    ),
    
    "basic_auth": SecretPattern(
        name="basic_auth",
        pattern=r"Basic\s+[a-zA-Z0-9+/]{20,}={0,2}",
        confidence="MEDIUM",
        entropy_threshold=2.5,
        exclude_files=[]
    ),
    
    "jenkins_api_token": SecretPattern(
        name="jenkins_api_token",
        pattern=r"jenkins[_-]?token[_-]?[a-zA-Z0-9]{32,}",
        confidence="MEDIUM",
        entropy_threshold=3.0,
        exclude_files=[]
    ),
    
    "certificate_key": SecretPattern(
        name="certificate_key",
        pattern=r"-----BEGIN CERTIFICATE-----",
        confidence="MEDIUM",
        entropy_threshold=2.0,
        exclude_files=[]
    ),

    "generic_secret_env": SecretPattern(
        name="generic_secret_env",
        pattern=r"(secret|key|token|password|api_key|api_secret)\s*=\s*['\"]([a-zA-Z0-9_\-!@#$%]{12,})['\"]",
        confidence="MEDIUM",
        entropy_threshold=2.8,
        exclude_files=["README.md"]
    ),
    
    "openai_api_key": SecretPattern(
        name="openai_api_key",
        pattern=r"sk-[a-zA-Z0-9]{20,}",
        confidence="HIGH",
        entropy_threshold=3.5,
        exclude_files=[]
    ),
    
    "huggingface_token": SecretPattern(
        name="huggingface_token",
        pattern=r"hf_[a-zA-Z0-9]{32,}",
        confidence="HIGH",
        entropy_threshold=3.5,
        exclude_files=[]
    ),
    
    "pinecone_api_key": SecretPattern(
        name="pinecone_api_key",
        pattern=r"pc-[a-zA-Z0-9]{32,}",
        confidence="HIGH",
        entropy_threshold=3.5,
        exclude_files=[]
    ),

}


def get_patterns_by_confidence(confidence: str = None):
    """Get patterns filtered by confidence level."""
    if confidence is None:
        return PATTERNS
    
    return {
        name: pattern 
        for name, pattern in PATTERNS.items()
        if pattern.confidence == confidence
    }


def get_pattern(name: str) -> SecretPattern:
    """Get a specific pattern by name."""
    return PATTERNS.get(name)