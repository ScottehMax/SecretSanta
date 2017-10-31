from flask import Flask, render_template, request, session, escape
from flask_mail import Mail, Message
from mongokit import Connection, Document, ObjectId
from werkzeug.security import generate_password_hash, check_password_hash

import random
from ConfigParser import RawConfigParser

config = RawConfigParser()
config.read('config.ini')

GLASWEGIAN_MODE = True

MONGODB_HOST = 'localhost'
MONGODB_PORT = 27017

MAIL_SERVER = config.get('Mail', 'MAIL_SERVER')
MAIL_PORT = config.get('Mail', 'MAIL_PORT')
MAIL_USE_SSL = config.get('Mail', 'MAIL_USE_SSL')
MAIL_USERNAME = config.get('Mail', 'MAIL_USERNAME')
MAIL_PASSWORD = config.get('Mail', 'MAIL_PASSWORD')
MAIL_DEFAULT_SENDER = config.get('Mail', 'MAIL_DEFAULT_SENDER')

app = Flask(__name__)
app.secret_key = ('\x8c\xf2\x7f\x1d\xe5\xbc\xd0' +
                  '\x03b\xe6\x0bZ\x1cx\xc6\xc6\xc9b@\x87')

app.config.from_object(__name__)

mail = Mail()
mail.init_app(app)

connection = Connection(app.config['MONGODB_HOST'],
                        app.config['MONGODB_PORT'])


@app.route('/')
def main():
    if 'username' not in session:
        return render_template('index.html')
    groups = list(group_col.Group.find({'owner': unicode(session['username'])}))
    print groups
    return render_template('rooms.html',
                           text='Logged in as %s!' % escape(session['username']),
                           groups=groups)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # note: write this
        result = create_user(request.form['username'],
                             request.form['email'],
                             request.form['password'])
        if result[0]:
            return render_template('basic.html', text=result, redirect="/")
        else:
            return render_template('register.html', error=result[1], username=request.form['username'], email=request.form['email'])
        # log user in, etc, etc.
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if check_user(username, password):
            # yay!
            session['username'] = username
            return render_template('basic.html', text='Success! You are now logged in.', redirect="/")
        else:
            return render_template('basic.html', text='Invalid username or password.', redirect="/login")
    return render_template('login.html')


@app.route('/logout')
def logout():
    # remove the username from the session if it's there
    session.pop('username', None)
    return render_template('basic.html', text='You are now logged out.', redirect="/")


@app.route('/create', methods=['GET', 'POST'])
def create():
    if request.method == 'POST':
        name = request.form['name']
        result = create_group(name, session['username'])
        if result[0]:
            return render_template('basic.html', text=result, redirect="/")
        else:
            return render_template('create.html', error=result[1])
    return render_template('create.html')


@app.route('/get/<o_id>')
def get(o_id):
    group = group_col.Group.find_one({'_id': ObjectId(o_id)})
    user_data = [(user, user_col.User.find_one({'username': user}).email) for user in group.users]
    if not group:
        text = "Group disny exist, lad." if GLASWEGIAN_MODE else "That group does not exist."
        return render_template('basic.html',
                               text=text, redirect="/")
    if group.owner != session.get('username'):
        text = "Hawl, that's not your group. Get tae." if GLASWEGIAN_MODE else "You do not have permission to manage that group."
        return render_template('basic.html',
                               text=text, redirect="/")
    print 'Getting group with ID %s...' % o_id
    return render_template('group.html',
                           groupname=group.name,
                           id=o_id,
                           user_data=user_data)


@app.route('/delete/<id>')
def delete(id):
    # delete here
    pass


@app.route('/adduser/<o_id>', methods=['GET', 'POST'])
def add_user(o_id):
    if request.method == 'POST':
        group = group_col.Group.find_one({'_id': ObjectId(o_id)})
        if group.owner != session.get('username'):
            return render_template('basic.html',
                                   text='That is NOT your group. PLEASE.', redirect="/")
        username = unicode(request.form['username'])
        if user_col.User.find_one({'username': username}):
            if username in group.users:
                return render_template('basic.html',
                                       text="User is already in the group.", redirect="/get/%s" % o_id)
            else:
                group.users.append(username)
                group.save()
                return render_template('basic.html',
                                       text="User %s added!" % username, redirect="/get/%s" % o_id)
        else:
            return render_template('basic.html',
                                   text="User does not exist.", redirect="/get/%s" % o_id)
    else:
        return render_template('basic.html',
                               text='Oi. Stop trying to break my webapp.', redirect="/")


def ss(l):
    l2 = l + []
    results = {}
    for u in l2:
        choice = random.choice(l)
        while choice == u:
            choice = random.choice(l)
        results[u] = choice
        l.remove(choice)
    return results


@app.route('/send/<o_id>')
def send(o_id):
    group = group_col.Group.find_one({'_id': ObjectId(o_id)})
    if group.owner != session.get('username'):
        return render_template('basic.html',
                               text='That is NOT your group. PLEASE.', redirect="/")
    users = group.users
    if len(users) <= 1:
        return render_template('basic.html',
                               text="There aren't enough people!", redirect="/get/%s" % o_id)
    results = ss(users)
    with mail.connect() as conn:
        for user in results:
            email = user_col.User.find_one({'username': user}).email
            msg = Message(body='Hello %s,\n\nYour secret santa is %s! Have fun!' % (user, results[user]),
                          subject="Your Secret Santa",
                          sender=("Secret Santa", "secretsanta@scotteh.me"))
            msg.add_recipient(email)
            conn.send(msg)
    return render_template('basic.html', text='Emails were sent!', redirect='/get/%s' % o_id)


def max_length(length):
    def validate(value):
        if len(value) <= length:
            return True
        raise Exception("Max length is %s!" % length)
    return validate


class User(Document):
    structure = {
        'username': unicode,
        'email': unicode,
        'password': unicode,
    }
    validators = {
        'username': max_length(50),
        'email': max_length(120)
    }
    use_dot_notation = True

    def __repr__(self):
        return '<User %r>' % (self.username)


class Group(Document):
    structure = {
        'name': unicode,
        'users': list,
        'owner': unicode,
    }
    use_dot_notation = True

    def __repr__(self):
        return '<Group %r>' % (self.name)


connection.register([User])
connection.register([Group])
user_col = connection['test'].users
group_col = connection['test'].groups


def create_user(username, email, password):
    if len(username) < 3:
        return (False, 'Your name is too short, it must be 3 or more characters!')
    if len(password) < 8:
        return (False, 'Your password must be at least 8 characters long.')
    if ' ' in username:
        return (False, 'Your name cannot contain any spaces.')
    if len(email) < 7 or '@' not in email:
        return (False, 'You must enter a valid email address!')
    user = user_col.User()
    if not user_col.User.find_one({'username': unicode(username)}):
        user.username = unicode(username)
        user.email = unicode(email)
        user.password = unicode(generate_password_hash(password))
        user.save()
        return (True, 'Success!')
    else:
        return (False, 'That user already exists.')


def check_user(username, password):
    user = user_col.User.find_one({'username': unicode(username)})
    if check_password_hash(user.password, password):
        return True
    return False


def create_group(name, username):
    if len(name) < 1 or len(name.replace(' ', '')) == 0:
        return (False, 'You must enter a name!')
    group = group_col.Group()
    group.name = name
    group.users = []
    group.owner = username
    group.save()
    return (True, 'Success!')

if __name__ == '__main__':
    app.run(debug=True)
