from flask import Flask, request, redirect, render_template_string
from flask_login import LoginManager, UserMixin, login_required, login_user
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = "group-h"
#Initialize Flask-Login to manage user sessions
login_manager = LoginManager(app)

#Using Werkzeug to hash password
users = {"user1": generate_password_hash("MyStrongPassword2754")}

#required code for flask login
class User(UserMixin):
    def __init__(self,id):
        self.id = id

#Flask-Login callback to reload a user from the session
@login_manager.user_loader
def load_user(id):return User(id) if id in users else None

login_page = """
<h2>Login Page</h2>
<form method="POST" action="/login-simple">
    <label>Username:</label>
    <input type="text" name="user"><br><br>
    <label>Password:</label>
    <input type="password" name="pass"><br><br>
    <button type="submit">Login</button>
</form>
"""
@app.route('/')
def home():
    return redirect('/login-simple')

@app.route('/login-simple', methods=['GET','POST'])
def login():
    if request.method == 'GET':
        return render_template_string(login_page)
    
    user_id = request.form['user']
    password = request.form['pass']
    # Verify user exists and password hash matches
    if user_id in users and check_password_hash(users[user_id], password):
        # Flask-Login handles session creation
        login_user(User(user_id))
        return "You have successfully logged in!"
    return "You have failed to login..."

@app.route('/Secret-tunnel')
#Blockes users if not logged in
@login_required
def Secret():
    return "All the company's financial Data"

if __name__ == "__main__":
    app.run(debug=True)