from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, jsonify, Response)
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import re, csv, io
from db_config import get_db_connection
import security_engine as se

app = Flask(__name__)
app.secret_key = "CHANGE_THIS_TO_RANDOM_LONG_STRING_abc123xyz789"

def login_required(f):
    @wraps(f)
    def w(*a, **kw):
        if 'user_id' not in session:
            flash("Please log in.", "warning")
            return redirect(url_for('login'))
        return f(*a, **kw)
    return w

def admin_required(f):
    @wraps(f)
    def w(*a, **kw):
        if session.get('role') != 'admin':
            flash("Admin access required.", "danger")
            return redirect(url_for('dashboard'))
        return f(*a, **kw)
    return w

def valid_email(e): return re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", e)

def strong_pwd(p):
    return (len(p) >= 8 and re.search(r"[A-Z]", p) and re.search(r"[a-z]", p)
            and re.search(r"\d", p) and re.search(r"[!@#$%^&*(),.?\":{}|<>]", p))

@app.route('/')
def index():
    return redirect(url_for('dashboard') if 'user_id' in session else url_for('login'))

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        u = request.form['username'].strip()
        e = request.form['email'].strip()
        p = request.form['password']
        if not re.match(r"^\w{3,50}$", u):
            flash("Username must be 3-50 alphanumeric chars.", "danger"); return redirect(url_for('register'))
        if not valid_email(e):
            flash("Invalid email.", "danger"); return redirect(url_for('register'))
        if not strong_pwd(p):
            flash("Weak password. Use 8+ chars, upper, lower, digit, symbol.", "danger")
            return redirect(url_for('register'))
        conn = get_db_connection(); cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE username=%s OR email=%s", (u,e))
        if cur.fetchone():
            flash("Username or email exists.", "danger"); cur.close(); conn.close()
            return redirect(url_for('register'))
        cur.execute("INSERT INTO users(username,email,password_hash) VALUES(%s,%s,%s)",
                    (u, e, generate_password_hash(p)))
        conn.commit(); cur.close(); conn.close()
        flash("Registered! Please log in.", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        u  = request.form['username'].strip()
        p  = request.form['password']
        ip = request.remote_addr or '0.0.0.0'
        ua = request.headers.get('User-Agent','')
        conn = get_db_connection(); cur = conn.cursor()
        if se.is_ip_blacklisted(cur, ip):
            se.log_login_attempt(cur, None, u, ip, ua, 0)
            conn.commit(); cur.close(); conn.close()
            flash("Your IP is blacklisted.", "danger")
            return redirect(url_for('login'))
        cur.execute("SELECT id,password_hash FROM users WHERE username=%s", (u,))
        row = cur.fetchone()
        if row:
            locked = se.is_account_locked(cur, row[0])
            if locked:
                se.log_login_attempt(cur, row[0], u, ip, ua, 0)
                conn.commit(); cur.close(); conn.close()
                flash(f"Account locked until {locked.strftime('%H:%M:%S')}", "danger")
                return redirect(url_for('login'))
        if row and check_password_hash(row[1], p):
            se.reset_failed_attempts(cur, row[0], ip)
            se.log_login_attempt(cur, row[0], u, ip, ua, 1)
            conn.commit()
            session['user_id'] = row[0]; session['username'] = u
            cur.execute("SELECT role FROM users WHERE id=%s", (row[0],))
            session['role'] = cur.fetchone()[0]
            cur.close(); conn.close()
            flash(f"Welcome back, {u}!", "success")
            return redirect(url_for('dashboard'))
        else:
            if row: se.register_failed_attempt(cur, row[0])
            se.log_login_attempt(cur, row[0] if row else None, u, ip, ua, 0)
            se.detect_brute_force(cur, ip)
            se.detect_credential_stuffing(cur)
            conn.commit(); cur.close(); conn.close()
            flash("Invalid credentials.", "danger")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear(); flash("Logged out.", "info"); return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users"); total_users = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM login_logs WHERE success=1"); succ = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM login_logs WHERE success=0"); fail = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM ip_blacklist"); bl = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM alerts WHERE created_at >= NOW() - INTERVAL 1 DAY")
    a24 = cur.fetchone()[0]
    cur.execute("""SELECT DATE(attempt_time), SUM(success=1), SUM(success=0)
                   FROM login_logs WHERE attempt_time >= NOW() - INTERVAL 7 DAY
                   GROUP BY DATE(attempt_time) ORDER BY 1""")
    timeline = cur.fetchall()
    cur.execute("""SELECT ip, COUNT(*) FROM login_logs WHERE success=0
                   GROUP BY ip ORDER BY COUNT(*) DESC LIMIT 5""")
    top_ips = cur.fetchall()
    cur.execute("SELECT alert_type, COUNT(*) FROM alerts GROUP BY alert_type")
    alert_breakdown = dict(cur.fetchall())
    cur.execute("""SELECT alert_type,message,severity,related_ip,created_at
                   FROM alerts ORDER BY created_at DESC LIMIT 8""")
    recent_alerts = cur.fetchall()
    cur.close(); conn.close()
    return render_template('dashboard.html',
        total_users=total_users, success_logins=succ, failed_logins=fail,
        blacklisted=bl, alerts_24h=a24, timeline=timeline, top_ips=top_ips,
        alert_breakdown=alert_breakdown, recent_alerts=recent_alerts)

@app.route('/api/live-stats')
@login_required
def api_live_stats():
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM login_logs WHERE success=0"); f = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM login_logs WHERE success=1"); s = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM alerts WHERE created_at >= NOW() - INTERVAL 1 HOUR")
    a = cur.fetchone()[0]
    cur.close(); conn.close()
    return jsonify({"failed": f, "success": s, "alerts_1h": a})

@app.route('/logs')
@login_required
@admin_required
def logs_view():
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("""SELECT id,username_attempted,ip,user_agent,success,attempt_time
                   FROM login_logs ORDER BY attempt_time DESC LIMIT 200""")
    rows = cur.fetchall(); cur.close(); conn.close()
    return render_template('login_logs.html', logs=rows)

@app.route('/logs/export')
@login_required
@admin_required
def logs_export():
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("""SELECT id,username_attempted,ip,user_agent,success,attempt_time
                   FROM login_logs ORDER BY attempt_time DESC""")
    rows = cur.fetchall(); cur.close(); conn.close()
    buf = io.StringIO(); w = csv.writer(buf)
    w.writerow(['ID','Username','IP','UserAgent','Success','Time'])
    w.writerows(rows)
    return Response(buf.getvalue(), mimetype='text/csv',
        headers={"Content-Disposition":"attachment;filename=login_logs.csv"})

@app.route('/blacklist')
@login_required
@admin_required
def blacklist_view():
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("SELECT id,ip,reason,auto_added,added_at FROM ip_blacklist ORDER BY added_at DESC")
    rows = cur.fetchall(); cur.close(); conn.close()
    return render_template('blacklist.html', rows=rows)

@app.route('/blacklist/add', methods=['POST'])
@login_required
@admin_required
def blacklist_add():
    ip = request.form['ip'].strip()
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        flash("Invalid IP.", "danger"); return redirect(url_for('blacklist_view'))
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("INSERT IGNORE INTO ip_blacklist(ip,reason,auto_added) VALUES(%s,%s,0)",
                (ip, request.form.get('reason','Manual block')))
    conn.commit(); cur.close(); conn.close()
    flash("IP blacklisted.", "success"); return redirect(url_for('blacklist_view'))

@app.route('/blacklist/remove/<int:bid>', methods=['POST'])
@login_required
@admin_required
def blacklist_remove(bid):
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("DELETE FROM ip_blacklist WHERE id=%s", (bid,))
    conn.commit(); cur.close(); conn.close()
    flash("Removed.", "info"); return redirect(url_for('blacklist_view'))

@app.route('/alerts')
@login_required
@admin_required
def alerts_view():
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("""SELECT id,alert_type,message,severity,related_ip,created_at
                   FROM alerts ORDER BY created_at DESC LIMIT 200""")
    rows = cur.fetchall(); cur.close(); conn.close()
    return render_template('alerts.html', rows=rows)

@app.route('/users')
@login_required
@admin_required
def users_view():
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("""SELECT id,username,email,role,failed_attempts,
                          locked_until,last_login,last_ip
                   FROM users ORDER BY created_at DESC""")
    rows = cur.fetchall(); cur.close(); conn.close()
    return render_template('users.html', rows=rows)

@app.route('/users/unlock/<int:uid>', methods=['POST'])
@login_required
@admin_required
def users_unlock(uid):
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=%s", (uid,))
    conn.commit(); cur.close(); conn.close()
    flash("User unlocked.", "success"); return redirect(url_for('users_view'))

@app.route('/users/promote/<int:uid>', methods=['POST'])
@login_required
@admin_required
def users_promote(uid):
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("UPDATE users SET role='admin' WHERE id=%s", (uid,))
    conn.commit(); cur.close(); conn.close()
    flash("User promoted.", "success"); return redirect(url_for('users_view'))

if __name__ == '__main__':
    app.run(debug=True)
