"""Test entropy calculation for secret detection."""

import pytest
from credlock.entropy import calculate_entropy, is_high_entropy, is_likely_secret
from credlock.scanner import scan_content


class TestEntropy:
    """Test entropy calculations."""
    
    def test_entropy_calculation(self):
        """Test basic entropy calculation"""
        assert calculate_entropy("aaaa") == 0.0
        random_str = "abc123XYZ!@#"
        entropy = calculate_entropy(random_str)
        assert entropy > 3.0
    
    def test_is_high_entropy(self):
        """Test high entropy detection."""
        assert is_high_entropy("AKIA7JKQWL2MXKBP9QVW", threshold=3.5)
        assert not is_high_entropy("aaabbbcccddd", threshold=3.5)
    
    def test_is_likely_secret_aws(self):
        """Test AWS key detection with entropy."""
        aws_key = "AKIA7JKQWL2MXKBP9QVW"
        assert is_likely_secret(aws_key, "aws_access_key")
    
    def test_is_likely_secret_password(self):
        """Test password detection with entropy."""
        strong_pass = "MyStr0ng!Pass@2024"
        assert is_likely_secret(strong_pass, "password_assignment")
    
    def test_npm_integrity_hash_filtered(self):
        """Test npm hashes don't match AKIA pattern."""
        npm_hash = "sha512-aBcD1234567890abcdef1234567890abcdef1234567890abcdef1234567890abc"
        
        # Should not match AKIA pattern (even with high entropy)
        findings = scan_content(npm_hash)
        aws_findings = [f for f in findings if f.pattern_name == "aws_access_key"]
        assert len(aws_findings) == 0
    
    def test_entropy_examples(self):
        """Test entropy values for various strings."""
        assert calculate_entropy("AKIA7JKQWL2MXKBP9QVW") > 3.0
        assert calculate_entropy("ghp_1234567890abcdefghijklmnopqrst1234") > 3.0
        assert calculate_entropy("Password must be 8 chars") > 2.5
    
    def test_github_token_entropy(self):
        """Test GitHub token entropy."""
        token = "ghp_1234567890abcdefghijklmnopqrst1234"
        assert is_likely_secret(token, "github_token")
    
    def test_private_key_entropy(self):
        """Test private key entropy."""
        key_header = "-----BEGIN RSA PRIVATE KEY-----"
        entropy = calculate_entropy(key_header)
        assert entropy >= 0.0
    
    def test_slack_token_entropy(self):
        """Test Slack token entropy."""
        token = "xoxb-1234567890-1234567890-abcdefghijklmn"
        assert is_likely_secret(token, "slack_bot_token")