from flask import Flask, redirect, url_for, session, request, render_template
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
    accounts = {'admin': {'passwordHash': "$2b$12$onqawEagzgR8R1iNRovnN.a7Z2FzdplZb0w.HuuB4uYeeIxPBuGri",
                          'salt': "$2b$12$onqawEagzgR8R1iNRovnN.", 'groups': ['admin']}}
    try:
        passw = bytes(passw, 'utf-8')
        return bytes(accounts[username]['passwordHash'], 'utf-8') == bcrypt.hashpw(passw, bytes(accounts[username]['salt'], 'utf-8'))
    except:
        return False

@app.route('/')#test this and index.html for no path in url
def indexPage():
    return redirect(url_for('loginPage'))

@app.route('/login', methods=['POST', 'GET'])
def loginPage():
    error = None
    if request.method == 'POST':
        if valid_login(request.form['username'],
                       request.form['password']):
            session['username'] = request.form['username']
            return redirect(url_for('overviewPage'))
        else:
            error = 'Invalid username/password'
    try:
        user = request.form['username']
    except KeyError:
        user = ""
    return render_template('logIn.html', user = user, error = error)

@app.route('/logout')
def logoutPage():
    try:
        session['username']
    except KeyError:
        return '''<h2>You were not logged in</h2>'''
    session.pop('username', None)
    return render_template('logOut.html')


@app.route('/overview')
def overviewPage():
    print(session)
    try:
        session['username']
    except KeyError:#might need more for account system to block
        return render_template('notLogin.html')
    return render_template('overview.html', user = session['username'])