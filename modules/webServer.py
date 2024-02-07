from flask import Flask
import secrets
import bcrypt

app = Flask(__name__)
app.secret_key = secrets.token_hex()

def valid_login(username:str, passw:str) -> bool:
    """Check if the given credentials are a valid account

    Args:
        username (str): The username to check
        passw (str): The password to check

    Returns:
        bool: If there is an account with the given credentials or not
    """
    if not username or not passw: return False
    global accounts
    try:
        passw = bytes(passw)
        return accounts[username]['passwordHash'] == bcrypt.hashpw(passw, accounts[username]['salt'])
    except:
        return False

@app.route('/login', methods=['POST', 'GET'])
def loginPage():
    error = None
    if request.method == 'POST':
        if valid_login(request.form['username'],
                       request.form['password']):
            session['username'] = request.form['username']
            return #send to different page
        else:
            error = 'Invalid username/password'
    return render_template('login.html', error=error)