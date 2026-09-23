"""
CredLock Pattern Database (FIXED)
50+ regex patterns for detecting common secrets
"""

PATTERNS = {
    # AWS Credentials
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "aws_secret_key": r"aws_secret_access_key\s*=\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?",
    
    # API Keys (Generic)
    "api_key_generic": r"api[_-]?key\s*[=:]\s*[\"']?([A-Za-z0-9\-_\.]{20,})[\"']?",
    "api_key_equals": r"[\"']?api_key[\"']?\s*[:=]\s*[\"']([^\"']+)[\"']",
    
    # GitHub Tokens (FIXED: lowered from 36 to 30 minimum)
    "github_token": r"gh[pousr]_[A-Za-z0-9_]{30,255}",
    "github_oauth": r"github_oauth_token\s*[:=]\s*[\"']?([A-Za-z0-9_]{40,})[\"']?",
    
    # Stripe Keys
    "stripe_key_live": r"sk_live_[0-9a-zA-Z]{20,}",
    "stripe_key_test": r"sk_test_[0-9a-zA-Z]{20,}",
    "stripe_publishable": r"pk_(live|test)_[0-9a-zA-Z]{20,}",
    
    # Database URLs
    "database_url": r"(mysql|postgres|mongodb|redis|oracle):\/\/[^@]+:[^@]+@",
    "postgres_url": r"postgres://[^:]+:[^@]+@[^/]+/",
    "mysql_url": r"mysql://[^:]+:[^@]+@[^/]+/",
    
    # Password Assignment
    "password_assignment": r"password\s*[=:]\s*[\"'](.{8,})[\"']",
    "passwd_assignment": r"passwd\s*[=:]\s*[\"'](.{8,})[\"']",
    "pwd_assignment": r"pwd\s*[=:]\s*[\"'](.{8,})[\"']",
    
    # Private SSH Keys
    "private_key_rsa": r"-----BEGIN RSA PRIVATE KEY-----",
    "private_key_openssh": r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "private_key_ec": r"-----BEGIN EC PRIVATE KEY-----",
    "private_key_dsa": r"-----BEGIN DSA PRIVATE KEY-----",
    "private_key_pgp": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    
    # JWT Tokens
    "jwt_token": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
    
    # Slack Tokens
    "slack_token": r"xox[abp]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
    "slack_webhook": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
    
    # Firebase Keys
    "firebase_key": r"AIza[0-9A-Za-z\-_]{35}",
    "firebase_url": r"https://[a-z0-9]+\.firebaseio\.com",
    
    # Google Cloud
    "gcp_key": r"AIza[0-9A-Za-z\-_]{35}",
    "gcp_service_account": r"\"type\"\s*:\s*\"service_account\"",
    
    # Microsoft Azure
    "azure_key": r"[a-zA-Z0-9/+=]{88,}",
    
    # SendGrid API Key
    "sendgrid_key": r"SG\.[A-Za-z0-9_-]{66}",
    
    # Mailchimp API Key
    "mailchimp_key": r"[0-9a-f]{32}-us[0-9]{1,2}",
    
    # Twilio Credentials
    "twilio_account_sid": r"AC[a-zA-Z0-9_]{32}",
    "twilio_auth_token": r"[0-9a-f]{32}",
    
    # GitHub OAuth
    "github_client_secret": r"ghcs_[A-Za-z0-9_]{48}",
    
    # SSH Private Key Alternative Format
    "ssh_private_key": r"BEGIN.*PRIVATE KEY",
    
    # Generic Token Pattern
    "generic_token": r"(token|secret|key)\s*[=:]\s*[\"']([A-Za-z0-9_\-\.]{20,})[\"']",
    
    # Environment Variables with Secrets
    "env_secret": r"(SECRET|PASSWORD|API_KEY|TOKEN)\s*[=:]\s*[\"']([^\"']+)[\"']",
    
    # Connection Strings
    "connection_string": r"Server=[^;]+;.*Password=[^;]+",
    "mongodb_connection": r"mongodb://[^:]+:[^@]+@",
    
    # Docker Environment
    "docker_env": r"ENV\s+(PASS|PASSWORD|SECRET|KEY|TOKEN)\s+[A-Za-z0-9_\-\.]+",
    
    # AWS Config
    "aws_config": r"\[aws_access_key_id\]|aws_secret_access_key",
    
    # HashiCorp Vault
    "vault_token": r"s\.[a-zA-Z0-9]{20,}",
    
    # NPM Token
    "npm_token": r"npm_[A-Za-z0-9]{36}",
    
    # PyPI Token
    "pypi_token": r"pypi-Ag[A-Za-z0-9_-]{36,}",
    
    # Authorization Header
    "auth_header": r"Authorization\s*:\s*Bearer\s+[A-Za-z0-9_\-\.]+",
    
    # Heroku API Key
    "heroku_key": r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    
    # DigitalOcean Token
    "digitalocean_token": r"dop_v1_[A-Za-z0-9]{20,}",
    
    # Datadog API Key
    "datadog_key": r"[a-f0-9]{32}",
    
    # New Relic License Key
    "newrelic_key": r"[a-z0-9]{40,}",
    
    # OAuth Access Token
    "oauth_token": r"oauth_token\s*[=:]\s*[\"']([A-Za-z0-9_\-\.]{20,})[\"']",
    
    # NEW PATTERN #50 - Artifactory API Key
    "artifactory_key": r"AKCp[A-Za-z0-9_]{50,}",
}

# Patterns to exclude from certain files
IGNORE_PATTERNS = [
    r".*\.git.*",
    r".*node_modules.*",
    r".*__pycache__.*",
    r".*tests.*",
    r".*\.pyc",
    r".*\.class",
    r".*\.o",
    r".*\.obj",
    r".*\.exe",
    r".*\.dll",
    r".*\.so",
    r".*\.dylib",
    r".*\.app",
    r".*\.deb",
    r".*\.rpm",
    r".*venv.*",
    r".*[/\\]env[/\\].*",
    r".*\.egg-info.*",
    r".*dist.*",
    r".*build.*",
    r".*\.DS_Store",
    r".*Thumbs\.db",
    r".*\.lock",
]

# File extensions to check
SCAN_EXTENSIONS = [
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".go", ".rs", ".c", ".cpp", ".h",
    ".rb", ".php", ".sh", ".bash", ".zsh",
    ".yml", ".yaml", ".json", ".xml", ".toml", ".ini", ".conf",
    ".env", ".properties", ".gradle", ".maven",
    ".sql", ".txt", ".md", ".log",
    ".config", ".cfg", ".cnf",
]

# Files that should never be committed
DANGEROUS_FILES = [
    ".env",
    ".env.local",
    ".env.production",
    ".env.staging",
    "secrets.json",
    "credentials.json",
    "aws_credentials",
    ".aws/credentials",
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    "id_rsa",
    "id_ed25519",
    "private_key",
    "private.key",
    "certificate.pem",
    "key.pem",
    "secret.key",
]