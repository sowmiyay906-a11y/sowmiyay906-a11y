from datetime import datetime, timedelta

MAX_FAILED_ATTEMPTS      = 5
LOCK_DURATION_MINUTES    = 15
BRUTE_FORCE_WINDOW_MIN   = 10
BRUTE_FORCE_THRESHOLD    = 8
AUTO_BLACKLIST_THRESHOLD = 15
CRED_STUFFING_USERS      = 5

def create_alert(cur, alert_type, message, severity, ip=None):
    cur.execute(
        "INSERT INTO alerts(alert_type,message,severity,related_ip) VALUES(%s,%s,%s,%s)",
        (alert_type, message[:500], severity, ip))

def is_ip_blacklisted(cur, ip):
    cur.execute("SELECT 1 FROM ip_blacklist WHERE ip=%s", (ip,))
    return cur.fetchone() is not None

def auto_blacklist_ip(cur, ip, reason):
    cur.execute("INSERT IGNORE INTO ip_blacklist(ip,reason,auto_added) VALUES(%s,%s,1)",
                (ip, reason[:255]))

def log_login_attempt(cur, user_id, username, ip, user_agent, success):
    cur.execute(
        "INSERT INTO login_logs(user_id,username_attempted,ip,user_agent,success) VALUES(%s,%s,%s,%s,%s)",
        (user_id, username, ip, (user_agent or '')[:255], success))

def is_account_locked(cur, user_id):
    cur.execute("SELECT locked_until FROM users WHERE id=%s", (user_id,))
    row = cur.fetchone()
    if row and row[0] and row[0] > datetime.now():
        return row[0]
    return None

def register_failed_attempt(cur, user_id):
    cur.execute("SELECT failed_attempts FROM users WHERE id=%s", (user_id,))
    row = cur.fetchone()
    if not row: return
    fails = row[0] + 1
    lock_until = None
    if fails >= MAX_FAILED_ATTEMPTS:
        lock_until = datetime.now() + timedelta(minutes=LOCK_DURATION_MINUTES)
        create_alert(cur, "ACCOUNT_LOCKOUT",
                     f"User ID {user_id} locked after {fails} failed attempts",
                     "High")
    cur.execute("UPDATE users SET failed_attempts=%s, locked_until=%s WHERE id=%s",
                (fails, lock_until, user_id))

def reset_failed_attempts(cur, user_id, ip):
    cur.execute("UPDATE users SET failed_attempts=0, locked_until=NULL, last_login=NOW(), last_ip=%s WHERE id=%s",
                (ip, user_id))

def detect_brute_force(cur, ip):
    since = datetime.now() - timedelta(minutes=BRUTE_FORCE_WINDOW_MIN)
    cur.execute("SELECT COUNT(*) FROM login_logs WHERE ip=%s AND success=0 AND attempt_time >= %s",
                (ip, since))
    recent_fails = cur.fetchone()[0]
    if recent_fails >= BRUTE_FORCE_THRESHOLD:
        create_alert(cur, "BRUTE_FORCE",
                     f"Brute-force from {ip}: {recent_fails} fails in {BRUTE_FORCE_WINDOW_MIN} min",
                     "Critical", ip)
    cur.execute("SELECT COUNT(*) FROM login_logs WHERE ip=%s AND success=0", (ip,))
    if cur.fetchone()[0] >= AUTO_BLACKLIST_THRESHOLD:
        auto_blacklist_ip(cur, ip, f"Auto: {AUTO_BLACKLIST_THRESHOLD}+ failed login attempts")

def detect_credential_stuffing(cur):
    since = datetime.now() - timedelta(minutes=BRUTE_FORCE_WINDOW_MIN)
    cur.execute("""SELECT ip, COUNT(DISTINCT username_attempted) FROM login_logs
                   WHERE success=0 AND attempt_time >= %s
                   GROUP BY ip HAVING COUNT(DISTINCT username_attempted) >= %s""",
                (since, CRED_STUFFING_USERS))
    for ip, n in cur.fetchall():
        create_alert(cur, "CREDENTIAL_STUFFING",
                     f"IP {ip} tried {n} different usernames", "Critical", ip)
        auto_blacklist_ip(cur, ip, f"Credential stuffing: {n} users targeted")
