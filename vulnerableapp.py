from flask import Flask, request, redirect, render_template_string, session
import sqlite3
import os

# ============================================================
# VULNERABLE VERSION - SecureTask (No Security Features)
#  CA2 - Secure Web Development
#
# Vulnerabilities present in this file:
#  1.  Plain text password storage (no hashing)
#  2.  SQL Injection on login
#  3.  SQL Injection on registration and tasks
#  4.  No CSRF protection
#  5.  Hardcoded weak secret key
#  6.  No rate limiting (brute force possible)
#  7.  No session timeout
#  8.  Broken access control (no ownership check on delete)
#  9.  Verbose error messages (information disclosure)
# 10.  No input validation
# ============================================================

app = Flask(__name__)

# VULNERABILITY 5: Hardcoded weak secret key
app.secret_key = "password123"

DB = "vulnerable.db"

# ── Database setup ─────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            user_id INTEGER
        )
    """)
    c.execute("SELECT * FROM users WHERE username = 'admin'")
    if not c.fetchone():
        # VULNERABILITY 1: Plain text password saved directly to database
        c.execute("INSERT INTO users (username, password, role) VALUES ('admin', 'admin123', 'admin')")
    conn.commit()
    conn.close()

# ── HTML Templates 

LOGIN_PAGE = """
<html><head><title>Login</title></head><body>
<h2>Login</h2>
<!-- VULNERABILITY 4: No CSRF token in form -->
<form method="POST" action="/login">
  <label>Username:</label><input type="text" name="username"><br><br>
  <label>Password:</label><input type="password" name="password"><br><br>
  <button type="submit">Login</button>
</form>
<p>No account? <a href="/register">Register here</a></p>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
</body></html>
"""

REGISTER_PAGE = """
<html><head><title>Register</title></head><body>
<h2>Register</h2>
<!-- VULNERABILITY 4: No CSRF token -->
<form method="POST" action="/register">
  <label>Username:</label>
  <!-- VULNERABILITY 10: No length or character validation -->
  <input type="text" name="username"><br><br>
  <label>Password:</label>
  <!-- VULNERABILITY 10: Single character password accepted -->
  <input type="password" name="password"><br><br>
  <button type="submit">Register</button>
</form>
<p>Have an account? <a href="/login">Login here</a></p>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
</body></html>
"""

DASHBOARD_PAGE = """
<html><head><title>Dashboard</title></head><body>
<h2>Welcome, {{ username }}!</h2>
{% if role == 'admin' %}<a href="/admin">Admin Panel</a> | {% endif %}
<a href="/logout">Logout</a>
<hr><h3>Your Tasks</h3>
{% if message %}<p style="color:green">{{ message }}</p>{% endif %}
{% for task in tasks %}
<p><b>{{ task[1] }}</b> - {{ task[2] }}
<a href="/delete-task/{{ task[0] }}">[Delete]</a></p>
{% else %}<p>No tasks yet.</p>{% endfor %}
<hr><h3>Add a Task</h3>
<!-- VULNERABILITY 4: No CSRF token -->
<form method="POST" action="/add-task">
  <input type="text" name="title" placeholder="Task title"><br><br>
  <input type="text" name="description" placeholder="Description"><br><br>
  <button type="submit">Add Task</button>
</form>
</body></html>
"""

ADMIN_PAGE = """
<html><head><title>Admin Panel</title></head><body>
<h2>Admin Panel</h2><a href="/dashboard">Back</a>
<h3>All Users</h3>
<!-- VULNERABILITY 1: Plain text passwords visible here -->
{% for user in users %}
<p>ID: {{ user[0] }} | Username: {{ user[1] }} | Password: {{ user[2] }} | Role: {{ user[3] }}</p>
{% endfor %}
<h3>All Tasks</h3>
{% for task in tasks %}
<p>{{ task[1] }} - {{ task[2] }} (User ID: {{ task[3] }})
<a href="/delete-task/{{ task[0] }}">[Delete]</a></p>
{% endfor %}
</body></html>
"""

# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route('/')
def home():
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
# VULNERABILITY 6: No @limiter.limit - unlimited brute force attempts allowed
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        # VULNERABILITY 2: SQL INJECTION
        # Try entering:  ' OR '1'='1  as the username to bypass login entirely
        query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
        try:
            c.execute(query)
            user = c.fetchone()
        except Exception as e:
            # VULNERABILITY 9: Raw database error shown to user - leaks DB info
            error = "Database error: " + str(e)
            conn.close()
            return render_template_string(LOGIN_PAGE, error=error)
        conn.close()
        if user:
            # VULNERABILITY 7: No session timeout configured
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[3]
            return redirect('/dashboard')
        else:
            # VULNERABILITY 9: Specific error message helps attacker enumerate usernames
            error = "Login failed - username or password not found in database"
    return render_template_string(LOGIN_PAGE, error=error)

@app.route('/register', methods=['GET', 'POST'])
# VULNERABILITY 6: No rate limiting - attacker can create thousands of accounts
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # VULNERABILITY 10: No validation at all - blank username/password accepted
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        # VULNERABILITY 3: SQL INJECTION on registration
        query = "INSERT INTO users (username, password, role) VALUES ('" + username + "', '" + password + "', 'user')"
        try:
            c.execute(query)
            conn.commit()
            conn.close()
            return redirect('/login')
        except Exception as e:
            # VULNERABILITY 9: Raw DB error exposed
            error = "Error: " + str(e)
            conn.close()
    return render_template_string(REGISTER_PAGE, error=error)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT * FROM tasks WHERE user_id = " + str(session['user_id']))
    tasks = c.fetchall()
    conn.close()
    return render_template_string(DASHBOARD_PAGE,
        username=session.get('username'),
        role=session.get('role'),
        tasks=tasks,
        message=request.args.get('message'))

@app.route('/add-task', methods=['POST'])
def add_task():
    if 'user_id' not in session:
        return redirect('/login')
    title = request.form['title']
    description = request.form['description']
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    # VULNERABILITY 3: SQL injection via task title or description field
    # Try entering: '); DROP TABLE tasks; -- as the title
    query = "INSERT INTO tasks (title, description, user_id) VALUES ('" + title + "', '" + description + "', " + str(session['user_id']) + ")"
    c.execute(query)
    conn.commit()
    conn.close()
    return redirect('/dashboard?message=Task added!')

@app.route('/delete-task/<task_id>')
# VULNERABILITY: Destructive action via GET - a malicious link can delete any task
def delete_task(task_id):
    if 'user_id' not in session:
        return redirect('/login')
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    # VULNERABILITY 8: No ownership check - any user can delete any task
    # Just visit /delete-task/1 to delete task with ID 1, regardless of owner
    c.execute("DELETE FROM tasks WHERE id = " + task_id)
    conn.commit()
    conn.close()
    return redirect('/dashboard?message=Task deleted.')

@app.route('/admin')
def admin():
    # VULNERABILITY 8: Only checks session value - not verified against database
    if session.get('role') != 'admin':
        return redirect('/dashboard')
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT * FROM users")
    users = c.fetchall()
    c.execute("SELECT * FROM tasks")
    tasks = c.fetchall()
    conn.close()
    return render_template_string(ADMIN_PAGE, users=users, tasks=tasks)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

if __name__ == '__main__':
    init_db()
    # VULNERABILITY: debug=True exposes full stack traces to users in production
    app.run(debug=True, port=5001)
