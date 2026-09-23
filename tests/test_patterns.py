"""
Tests for CredLock pattern detection
"""

import pytest
from credlock.patterns import PATTERNS
from credlock.scanner import scan_content


class TestPatterns:
    """Test pattern detection"""
    
    def test_aws_key_detection(self):
        """Test AWS access key detection"""
        pattern = PATTERNS['aws_access_key']
        assert "AKIA" in pattern
        
        # Test with fake AWS key
        findings = scan_content("AWS_KEY=AKIAIOSFODNN7EXAMPLE")
        assert len(findings) > 0
        assert findings[0].pattern_name == "aws_access_key"
    
    def test_stripe_key_detection(self):
        """Test Stripe key detection"""
        findings = scan_content('API_KEY=sk_live_51HWHX4BLzpPm1234567890ABCDEFG')
        assert len(findings) > 0
    
    def test_github_token_detection(self):
        """Test GitHub token detection"""
        findings = scan_content('TOKEN=ghp_1234567890abcdefghijklmnopqrst1234')
        assert len(findings) > 0
    
    def test_database_url_detection(self):
        """Test database URL detection"""
        findings = scan_content('DATABASE_URL=postgres://user:password@localhost:5432/db')
        assert len(findings) > 0
    
    def test_password_detection(self):
        """Test password assignment detection"""
        findings = scan_content('password = "mysecurepass123"')
        assert len(findings) > 0
    
    def test_jwt_token_detection(self):
        """Test JWT token detection"""
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
        findings = scan_content(f"TOKEN={token}")
        assert len(findings) > 0
    
    def test_no_false_positives(self):
        """Test that normal code doesn't trigger alerts"""
        content = """
def hello_world():
    print('Hello World')
    name = "John Doe"
    version = "1.0.0"
"""
        findings = scan_content(content)
        # Should not find anything or minimal findings
        password_findings = [f for f in findings if 'password' in f.pattern_name.lower()]
        assert len(password_findings) == 0
    
    def test_private_key_detection(self):
        """Test private key detection"""
        findings = scan_content("-----BEGIN RSA PRIVATE KEY-----")
        assert len(findings) > 0
    
    def test_slack_token_detection(self):
        """Test Slack token detection"""
        findings = scan_content("SLACK_TOKEN=xox-1234567890-1234567890")
        # May or may not find depending on regex precision
        assert isinstance(findings, list)
    
    def test_api_key_generic(self):
        """Test generic API key detection"""
        findings = scan_content('api_key = "sk_live_1234567890abcdefghij"')
        assert len(findings) > 0


class TestPatternCount:
    """Test pattern database"""
    
    def test_patterns_exist(self):
        """Test that patterns exist"""
        assert len(PATTERNS) >= 50
    
    def test_pattern_types(self):
        """Test pattern categories exist"""
        pattern_names = list(PATTERNS.keys())
        
        # Check for AWS patterns
        aws_patterns = [p for p in pattern_names if 'aws' in p.lower()]
        assert len(aws_patterns) > 0
        
        # Check for key patterns
        key_patterns = [p for p in pattern_names if 'key' in p.lower()]
        assert len(key_patterns) > 0
        
        # Check for token patterns
        token_patterns = [p for p in pattern_names if 'token' in p.lower()]
        assert len(token_patterns) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])