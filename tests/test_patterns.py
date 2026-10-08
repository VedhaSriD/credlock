"""Test secret pattern detection."""

import pytest
from credlock.patterns import PATTERNS, SecretPattern
from credlock.scanner import scan_content


class TestPatterns:
    """Test individual pattern detection."""
    
    def test_aws_key_detection(self):
        """Test AWS access key detection"""
        pattern = PATTERNS['aws_access_key']
        # FIX: Access pattern.pattern (the regex string)
        assert "AKIA" in pattern.pattern
        assert isinstance(pattern, SecretPattern)
    
    def test_stripe_key_detection(self):
        """Test Stripe key detection"""
        findings = scan_content('STRIPE_KEY=sk_live_51HqLkFBPZmKL2jQ9k3m4n5p6q7r8s9t0')
        assert len(findings) > 0
        assert findings[0].pattern_name == "stripe_key_live"
    
    def test_github_token_detection(self):
        """Test GitHub token detection"""
        findings = scan_content('TOKEN=ghp_1234567890abcdefghijklmnopqrst1234567890')
        assert len(findings) > 0, f"GitHub token not detected. Findings: {findings}"
    
    def test_database_url_detection(self):
        """Test database URL detection"""
        findings = scan_content('DB_URL=postgres://user:mysecretpass123@localhost:5432/mydb')
        assert len(findings) > 0
    
    def test_password_detection(self):
        """Test password detection"""
        findings = scan_content('password = "MySecurePassword123"')
        assert len(findings) > 0
    
    def test_jwt_token_detection(self):
        """Test JWT token detection"""
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        findings = scan_content(f"JWT={token}")
        assert len(findings) > 0
    
    def test_private_key_detection(self):
        """Test private key detection"""
        findings = scan_content("-----BEGIN RSA PRIVATE KEY-----")
        assert len(findings) > 0, "Private key not detected"
    
    def test_slack_token_detection(self):
        """Test Slack token detection"""
        findings = scan_content('SLACK_TOKEN=xoxb-1234567890-1234567890-abcdefghijklmn')
        assert len(findings) > 0
    
    def test_api_key_generic(self):
        """Test generic API key detection"""
        findings = scan_content('api_key = "sk_test_1234567890abcdefghij"')
        assert len(findings) > 0
    
    def test_no_false_positives(self):
        """Test that normal code doesn't trigger false positives"""
        normal_code = """
        def hello():
            name = "John"
            age = 30
            email = "user@example.com"
            return name
        """
        findings = scan_content(normal_code)
        # Should find few or no HIGH confidence findings
        high_conf = [f for f in findings if f.confidence == "HIGH"]
        assert len(high_conf) == 0


class TestPatternCount:
    """Test that we have enough patterns."""
    
    def test_patterns_exist(self):
        """Test that patterns exist"""
        assert len(PATTERNS) >= 50, f"Only {len(PATTERNS)} patterns, need 50+"
    
    def test_pattern_types(self):
        """Test that we have different pattern types"""
        aws_patterns = [p for p in PATTERNS.keys() if 'aws' in p.lower()]
        github_patterns = [p for p in PATTERNS.keys() if 'github' in p.lower()]
        
        assert len(aws_patterns) >= 3, f"Only {len(aws_patterns)} AWS patterns"
        assert len(github_patterns) >= 2, f"Only {len(github_patterns)} GitHub patterns"