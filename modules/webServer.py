import flask
from flask_sqlalchemy import SQLAlchemy
import flask_login
import secrets
import bcrypt

app = flask.Flask(__name__)
app.secret_key = secrets.token_hex()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'

db = SQLAlchemy()

class User(db.Model):
    """A User in the database
    """
    __tablename__ = 'users'

    username = db.Column(db.String, primary_key=True)
    password = db.Column(db.String)
    salt = db.Column(db.String)
    authenticated = db.Column(db.Boolean, default=False)
    groups = db.Column(db.String, default='users')

    def is_active(self):
        """True, as all users are active."""
        return True

    def get_id(self):
        return self.username

    def is_authenticated(self):
        """Return True if the user is authenticated."""
        return self.authenticated

    def is_anonymous(self):
        """False, as anonymous users aren't supported."""
        return False
    
class Group(db.Model):
    """A Group in the database
    """
    __tablename__ = "groups"
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String)
    
    def get_id(self):
        return self.id
    
    def get_name(self):
        return self.name
    
class Device(db.Model):
    """A Device connected to the server
    """
    __tablename__= "devices"
    
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String)
    user = db.Column(db.String)
    os = db.Column(db.String)
    hwid = db.Column(db.String)
    
    def get_id(self):
        return self.id
    
    def get_os(self):
        return self.os

'''userTable = db.Table(
    'users',
    sa.Column('username', sa.String, primary_key=True),
    sa.Column('password', sa.String),
    sa.Column('authenticated', sa.Boolean),
    sa.Column('groups', sa.String)
)'''

db.init_app(app)
with app.app_context():
    db.create_all()

login_manager = flask_login.LoginManager()
login_manager.init_app(app)
login_manager.refresh_view = '/login'
login_manager.login_view = '/login'
    
@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(user_id)

def valid_login(username:str, passw:str) -> bool:
    """Check if the given credentials are a valid account

    Args:
        username (str): The username to check
        passw (str): The password to check

    Returns:
        bool: If there is an account with the given credentials or not
    """
    if not username or not passw: return False
    user = User.query.get(username)
    print(user)
    if not user: return False
    try:
        passw = bytes(passw, 'utf-8')
        uPassword = bytes(user.password, 'utf-8')
        return bcrypt.checkpw(passw, uPassword)
    except:
        return False

def addAccount(username:str, passw:str, isAdmin:bool = False) -> str:
    """Add a user to the database

    Args:
        username (str): The username of the account to add
        passw (str): The password of the account to add

    Returns:
        str: If the account was created successfully or not
    """
    if not username or not passw: return "All fields are required"
    user = User.query.get(username)
    if user: return "An account with this username already exists"
    passw = bytes(passw, 'utf-8')
    salt = bcrypt.gensalt(12)
    passw = str(bcrypt.hashpw(passw, salt))[2:-1]
    groups = ['users']
    if isAdmin: groups.append('admins')
    newUser = User(username=username, password=str(passw), salt=str(salt), groups=",".join(groups))
    db.session.add(newUser)
    db.session.commit()
    return 'Account created successfully'

with app.app_context():
    print(addAccount('admin', 'test', True))
    print(addAccount('user', 'userTest', False))

@app.route('/')
def indexPage():
    return flask.redirect(flask.url_for('loginPage'))

@app.route('/login', methods=['POST', 'GET'])
def loginPage():
    error = None
    if flask.request.method == 'POST':
        if valid_login(flask.request.form['username'],
                       flask.request.form['password']):
            user = User.query.get(flask.request.form['username'])
            user.authenticated = True
            db.session.commit()
            flask_login.login_user(user, remember=True)
            next = flask.request.args.get('next')
            '''if not url_has_allowed_host_and_scheme(next, flask.request.host):
                return flask.abort(400)'''
            return flask.redirect(next or flask.url_for('overviewPage'))
        else:
            error = 'Invalid username/password'
    if flask_login.login_remembered():
        return flask.redirect(flask.url_for('overviewPage'))
    try:
        user = flask.request.form['username']
    except KeyError:
        user = ""
    return flask.render_template('logIn.html', user = user, error = error)

@app.route('/logout')
@flask_login.login_required
def logoutPage():
    user = User.query.get(flask_login.current_user.username)
    user.authenticated = False#might not need ths due to flask_login.logout_user
    db.session.commit()
    flask_login.logout_user()
    return flask.render_template('logOut.html')#might just want to redirect to login page


@app.route('/overview')
@flask_login.login_required
def overviewPage():
    return flask.render_template('overview.html', user = flask_login.current_user.username)