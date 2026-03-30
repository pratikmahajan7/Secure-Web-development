from flask import Flask, request, session, redirect, render_template_string

app = Flask(__name__)
app.secret_key = "group-h"

# Fake user database (plaintext on purpose)
users = {"user1": "123456789"}

#Checks if the username is in the fake user database
def username_exists(username):
    return username in users

#Checks if the entered password matches the stored password
def password_matches(username, password):
    return users.get(username) == password

#Preforms manual checks on users input 
def validate_login(username, password):
    if username is None or username == "":
        return False
    if password is None or password == "":
        return False
    if not username_exists(username):
        return False
    if not password_matches(username, password):
        return False
    return True

#Manualy creating mulltiple different session verialbles
def create_session(username):
    session['logged_in'] = True
    session['user'] = username
    session['session_valid'] = True
    session['auth_level'] = "basic"

#Checks whether a user is authenticated  
def is_authenticated():
    return (
        session.get('logged_in') and
        session.get('user') and
        session.get('session_valid')
    )

login_page = """
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f6f8;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .login-box {
            background: white;
            padding: 25px;
            border-radius: 8px;
            width: 300px;
            box-shadow: 0 4px 10px rgba(0,0,0,0.1);
        }
        h2 { text-align: center; }
        label { font-size: 14px; }
        input {
            width: 95%;
            padding: 8px;
            margin-top: 4px;
            margin-bottom: 15px;
        }
        button {
            width: 100%;
            padding: 10px;
            background-color: #4a67ff;
            color: white;
            border: none;
            cursor: pointer;
        }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Login</h2>
        <form method="POST">
            <label>Username</label>
            <input type="text" name="user" required>
            <label>Password</label>
            <input type="password" name="pass" required>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    return redirect('/login-complex')

@app.route('/login-complex', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template_string(login_page)

    #Handles login submissions manually 
    username = request.form['user']
    password = request.form['pass']

    if validate_login(username, password):
        create_session(username)
        return "You have successfully logged in!"

    return "You have failed to login..."

@app.route('/Secret-tunnel')
def Secret():
    if not session.get('logged_in'):
        return redirect('/login-complex')
    return "All the company's financial Data"

if __name__ == "__main__":
    app.run(debug=True)
