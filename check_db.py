import sqlite3
from cryptography.fernet import Fernet

# Load encryption key
with open('db.key', 'rb') as f:
    fernet = Fernet(f.read())

def decrypt(token):
    try:
        return fernet.decrypt(token.encode()).decode()
    except:
        return '(encrypted)'

conn = sqlite3.connect('mtvs_scans.db')
c = conn.cursor()

# ─────────────────────────────────────────
print("\n" + "="*60)
print("         MTVS ADMIN DASHBOARD")
print("="*60)

# ─── USERS ───────────────────────────────
print("\n📋 ALL REGISTERED USERS")
print("-"*60)
c.execute("SELECT * FROM users")
users = c.fetchall()

# Get column names
c.execute("PRAGMA table_info(users)")
user_cols = [col[1] for col in c.fetchall()]
print("Columns:", user_cols)
print()

for user in users:
    user_dict = dict(zip(user_cols, user))
    print(f"ID         : {user_dict.get('id')}")
    print(f"Email      : {decrypt(user_dict.get('email_enc', ''))}")
    print(f"Name       : {decrypt(user_dict.get('name_enc', ''))}")
    print(f"Plan       : {user_dict.get('plan', 'basic').upper()}")
    print(f"Created    : {user_dict.get('created_at')}")
    print(f"Last Login : {user_dict.get('last_login')}")
    print("-"*60)

print(f"\n✅ Total Users: {len(users)}")

# ─── SCANS ───────────────────────────────
print("\n🔍 ALL SCAN HISTORY")
print("-"*60)

# Check scans columns
c.execute("PRAGMA table_info(scans)")
scan_cols = [col[1] for col in c.fetchall()]
print("Columns:", scan_cols)
print()

c.execute("SELECT * FROM scans ORDER BY id DESC")
scans = c.fetchall()

for scan in scans:
    scan_dict = dict(zip(scan_cols, scan))
    print(f"Scan ID    : {scan_dict.get('id')}")
    print(f"Target     : {scan_dict.get('target')}")
    print(f"Time       : {scan_dict.get('scan_time')}")
    print(f"Plan       : {scan_dict.get('plan', 'basic').upper()}")
    print(f"Total      : {scan_dict.get('total_checks')} checks")
    print(f"Vulns      : {scan_dict.get('vuln_count')}")
    print(f"Warnings   : {scan_dict.get('warn_count')}")
    print(f"Passed     : {scan_dict.get('ok_count')}")
    print("-"*60)

print(f"\n✅ Total Scans: {len(scans)}")

# ─── PAYMENTS ────────────────────────────
print("\n💳 PAYMENT / PLAN SUMMARY")
print("-"*60)

c.execute("SELECT plan, COUNT(*) FROM users GROUP BY plan")
plan_counts = c.fetchall()
for plan, count in plan_counts:
    emoji = '🆓' if plan == 'basic' else '⭐' if plan == 'medium' else '👑'
    print(f"{emoji} {(plan or 'basic').upper():10} : {count} user(s)")

# ─── SCAN RESULTS ────────────────────────
print("\n📊 SCAN RESULTS TABLE")
print("-"*60)
c.execute("PRAGMA table_info(scan_results)")
result_cols = [col[1] for col in c.fetchall()]
print("Columns:", result_cols)

c.execute("SELECT * FROM scan_results LIMIT 5")
results = c.fetchall()
for r in results:
    result_dict = dict(zip(result_cols, r))
    print(f"ID: {result_dict.get('id')} | "
          f"Scan: {result_dict.get('scan_id')} | "
          f"Tool: {result_dict.get('tool')} | "
          f"Status: {result_dict.get('status')} | "
          f"Threat: {result_dict.get('threat_level')}")

print("\n" + "="*60)
print("           END OF ADMIN REPORT")
print("="*60)

conn.close()