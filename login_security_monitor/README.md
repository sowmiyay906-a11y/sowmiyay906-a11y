# Login Security Monitoring System

A dark-themed SOC-style mini-SIEM web application built with Flask + MySQL that monitors login activity, detects attacks, and alerts administrators.

## Prerequisites

- Python 3.10+
- XAMPP (MySQL running on localhost, user=root, password=empty)

## Setup

### 1. Install Python dependencies

```bash
cd login_security_monitor
pip install -r requirements.txt
```

### 2. Create the database

Start XAMPP MySQL, then import the schema:

```bash
mysql -u root < database.sql
```

Or open phpMyAdmin and import `database.sql`.

### 3. Run the app

```bash
python app.py
```

Visit http://127.0.0.1:5000

## First Admin User

Register an account, then manually promote it to admin in MySQL:

```sql
USE login_security_db;
UPDATE users SET role='admin' WHERE username='your_username';
```

Log out and back in to see the admin pages.

## Features

- **User Registration & Login** — PBKDF2-SHA256 hashed passwords (Werkzeug)
- **Login Logging** — Every attempt recorded with IP and User-Agent
- **Account Lockout** — 5 failed attempts locks the account for 15 minutes
- **Brute-Force Detection** — 8+ failures from one IP in 10 minutes triggers a Critical alert
- **Auto-Blacklist** — IPs with 15+ total failed attempts are blacklisted automatically
- **Credential Stuffing Detection** — 1 IP trying 5+ distinct usernames triggers a Critical alert
- **Dashboard** — Stat cards, 7-day login timeline (line chart), alert type breakdown (doughnut chart), top offending IPs, recent alerts
- **Admin Pages** — Login Logs (with CSV export), Alerts, IP Blacklist management, User management (unlock/promote)

## Security Practices

- Parameterized SQL queries (`%s` placeholders) everywhere
- Password hashing via `generate_password_hash` / `check_password_hash`
- Role-based access control via decorators (`@login_required`, `@admin_required`)
- Session management with Flask signed cookies
- Input validation: username `\w{3,50}`, valid email regex, strong password (8+ chars, upper, lower, digit, symbol)

## File Structure

```
login_security_monitor/
├── app.py              # Flask application with all routes
├── db_config.py        # MySQL connection helper
├── security_engine.py  # Threat detection logic
├── requirements.txt    # Python dependencies
├── database.sql        # Schema + seed data
├── README.md
├── templates/          # Jinja2 HTML templates
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── login_logs.html
│   ├── blacklist.html
│   ├── alerts.html
│   └── users.html
└── static/
    └── style.css        # Dark SOC theme
```

## Configuration

Database settings are in `db_config.py`:

```python
host="localhost"
user="root"
passwd=""
db="login_security_db"
```

Change `app.secret_key` in `app.py` to a random string for production use.
