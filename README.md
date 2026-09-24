# CredLock 🔐

**Prevent accidental credential commits to Git**

CredLock is an automatic secret detection tool that scans your code before pushing to GitHub. It detects 50+ types of secrets (API keys, passwords, tokens, private keys) and blocks commits if sensitive data is found.

## 🎯 Features

- ✅ **50+ Detection Patterns**: Detects AWS keys, API tokens, passwords, database URLs, private keys, JWT tokens, and more
- ✅ **Automatic Git Integration**: Pre-commit hook runs automatically before every push
- ✅ **Zero Configuration**: Works out of the box, no complex setup
- ✅ **Beautiful Terminal Output**: Color-coded, formatted scan results
- ✅ **Scan History**: Tracks all scans locally in JSON format
- ✅ **Custom Patterns**: Add your own detection rules
- ✅ **Cross-Platform**: Works on macOS, Linux, and Windows
- ✅ **Fast**: Scans directories in milliseconds

  ## 📸 Demo
  
<img width="1605" height="758" alt="Screenshot 2026-09-24 122759" src="https://github.com/user-attachments/assets/e3a47c74-0535-4e9d-a1c2-ee43bb999fce" />
<img width="1157" height="422" alt="Screenshot 2026-09-24 122814" src="https://github.com/user-attachments/assets/8b187f81-1ad7-42ad-9d8e-210594b4797f" />
<img width="1445" height="667" alt="Screenshot 2026-09-24 122822" src="https://github.com/user-attachments/assets/7eeca2a0-6a84-4a6e-8580-81c3e68fd2c6" />
<img width="822" height="450" alt="Screenshot 2026-09-24 122850" src="https://github.com/user-attachments/assets/d490044e-9e9b-4b00-a501-d948253a9628" />





## 📦 Installation

### From PyPI (Recommended)
```bash
pip install credlock
```

### From Source
```bash
git clone https://github.com/yourusername/credlock.git
cd credlock
pip install -e .
```

## 🚀 Quick Start

### 1. Install CredLock
```bash
pip install credlock
```

### 2. Setup Git Hook in Your Project
```bash
cd your-project
credlock setup-git

✅ Git pre-commit hook installed!
```

### 3. That's It!
Now every time you `git push`, CredLock will automatically scan for secrets:

```bash
$ git push origin main

🔍 Running CredLock...
✅ No secrets found. Push allowed!
```

## 📋 Commands

### Scan Directory
```bash
credlock scan              # Scan current directory
credlock scan /path/to/dir # Scan specific directory
```

### View Scan History
```bash
credlock history           # Show last 10 scans
credlock history --limit=5 # Show last 5 scans
```

### Configure Settings
```bash
credlock configure         # Interactive configuration
```

### Show Version
```bash
credlock --version
```

## 🔍 What Does It Detect?

### AWS Credentials
- AWS Access Key ID: `AKIA...`
- AWS Secret Access Key
- AWS Config files

### API Keys
- Generic API keys
- GitHub tokens
- Stripe keys (live and test)
- Firebase keys
- SendGrid API keys

### Passwords & Secrets
- Password assignments
- Database URLs (MySQL, PostgreSQL, MongoDB)
- Private SSH keys
- JWT tokens

### Communication Tokens
- Slack tokens
- Discord webhooks
- Telegram tokens

### Cloud Providers
- Google Cloud credentials
- Azure keys
- DigitalOcean tokens
- Heroku API keys

### More
- Environment variables with secrets
- Authorization headers
- OAuth tokens
- **50+ total patterns**

## 📝 Example Output

### When Secrets Are Found
```
🔍 Scanning current directory...

⛔ SECRETS DETECTED! Found 3 potential secrets

📄 .env (2 secrets)
  Line 2:  [aws_access_key] AWS_ACCESS_KEY_ID=AKIA...
  Line 3:  [database_password] DB_PASSWORD=mysecret123

📄 src/config.js (1 secret)
  Line 45: [stripe_key] API_KEY = "sk_live_4eC39HqLyjWDar..."

❌ PUSH BLOCKED - 3 SECRETS FOUND

Recommendations:
1. Move secrets to .env file
2. Add .env to .gitignore
3. Use environment variables in code

$ echo ".env" >> .gitignore
$ git rm --cached .env
$ git commit --amend
$ git push origin main
```

### When No Secrets Found
```
🔍 Scanning current directory...
✅ No secrets found. Scan clean!

Files scanned: 15
Duration: 0.234 seconds
```

## ⚙️ Configuration

CredLock is configured via `~/.credlock/config.yaml`:

```yaml
patterns_enabled: 50
custom_patterns: {}
ignored_files:
  - .git/*
  - node_modules/*
  - __pycache__/*
auto_scan: true
```

### Add Custom Pattern
```bash
credlock configure

Choose: 1 (Add custom pattern)
Pattern name: my_api_key
Regex: MY_KEY_[A-Z0-9]{32}
```

## 🔒 Security Notes

- **Secrets are NOT stored**: CredLock only detects and blocks commits
- **No network calls**: Everything runs locally
- **Scan history is local**: Stored in `~/.credlock/history.json`
- **No data collection**: Your code never leaves your machine

## 📚 How It Works

1. **Pre-commit Hook**: Git runs CredLock before every push
2. **File Scanning**: Reads all project files (respects .gitignore)
3. **Pattern Matching**: Uses 50+ regex patterns to detect secrets
4. **Reporting**: Shows findings with file names and line numbers
5. **Exit Code**: Returns 1 if secrets found (blocks push), 0 if clean

## 🐛 Troubleshooting

### "credlock: command not found"
Ensure CredLock is installed globally:
```bash
pip install credlock
which credlock  # Should show /path/to/credlock
```

### Pre-commit hook not running
Check hook is installed and executable:
```bash
cat .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

### False positives (normal code flagged as secret)
Add custom ignore patterns in config:
```bash
credlock configure
# Choose to disable specific patterns
```

### Want to force push anyway?
You can temporarily bypass CredLock:
```bash
# This skips the pre-commit hook
git push --no-verify
```

But don't make this a habit! 🚨

## 📊 Performance

- Scans 100+ files in **<1 second**
- Minimal CPU/memory overhead
- No impact on normal Git workflow

## 🤝 Contributing

Found a bug? Want to add more patterns? Contributions welcome!

1. Fork the repository
2. Create a branch: `git checkout -b feature/new-pattern`
3. Add tests for new patterns
4. Submit a pull request

## 📜 License

MIT License - see LICENSE file for details

## ⭐ Support

- **Documentation**: Read this README
- **Issues**: Report bugs on GitHub
- **Discussions**: Ask questions in GitHub Discussions

## 🎓 Interview Points

When asked about CredLock:

- **"What problem does it solve?"** → Prevents accidental secret commits, which happen all the time
- **"How does it work?"** → Git pre-commit hook + regex pattern matching
- **"Why local storage?"** → Fast, no dependencies, users control their data
- **"How is it different?"** → Better UX than existing tools, modern CLI, easy setup
- **"What's the hardest part?"** → Balancing security (not too many patterns) with usability (not too many false positives)

## 📈 Future Enhancements

- [ ] Team shared config (EnvVault integration)
- [ ] Real-time monitoring dashboard
- [ ] Slack/email notifications
- [ ] Repository statistics
- [ ] CI/CD pipeline integration
- [ ] Custom rule templates

---

Made with ❤️ for developers who value security

**Star this repo if you found it useful!** ⭐
