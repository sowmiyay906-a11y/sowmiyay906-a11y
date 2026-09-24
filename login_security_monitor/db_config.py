import MySQLdb

def get_db_connection():
    return MySQLdb.connect(
        host="localhost",
        user="root",
        passwd="",                  # XAMPP default empty
        db="login_security_db",
        charset="utf8mb4"
    )
