from flask import Flask, request, redirect, render_template, session, flash, url_for
from mysqlconnection import MySQLConnector
import re
import datetime
import time
import os, binascii
import md5

# Name Regular Expression
NAME_REGEX = re.compile(r'^[a-zA-Z]+$')

# Email Regular Expression
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

PW_REGEX = re.compile(r'^.*(?=.{8,})(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).*$')

app = Flask(__name__)

mysql = MySQLConnector(app,'wall')

app.secret_key = 'TheWallKey'

@app.route('/')

def index():
    goto = ''
    
    if 'session_id' in session:
        goto = '/theWall'
    else:
        if not 'method' in session:
            session['method']='register'

        goto = '/'+session['method']

    return redirect(goto)

@app.route('/theWall')
def theWall():
    
    if 'first_name' in session:
        session.pop('first_name')
    if 'last_name' in session:
        session.pop('last_name')
    if 'email' in session:
        session.pop('email')
    if 'method' in session:
        session.pop('method')

    if 'session_id' in session:
        query = "SELECT * FROM users where id = {}".format(session['session_id'])
        user = mysql.query_db(query)

        msgQuery = "SELECT users.id, concat(users.first_name, ' ', users.last_name) as full_name, messages.id, messages.user_id, messages.message, messages.created_at, DATE_FORMAT(messages.created_at, '%M %D %Y') as date FROM messages JOIN users on messages.user_id = users.id ORDER BY messages.created_at DESC"
        messages = mysql.query_db(msgQuery)

        commentQuery = "SELECT concat(users.first_name, ' ', users.last_name) as full_name, comments.id, comments.message_id, comments.comment, comments.created_at, DATE_FORMAT(comments.created_at, '%M %D %Y') as date FROM comments LEFT JOIN users on comments.user_id = users.id ORDER BY comments.created_at ASC"
        comments = mysql.query_db(commentQuery)

        #print comments

        return render_template('wall.html', user=user[0], messages=messages, comments=comments)
    else:
        return redirect('/login')

@app.route('/validate_user', methods=['POST'])
def validate_user():

    valid = True
    confirm_pw = ''
    goto = '/'+session['method']

    session['email'] = email = request.form['email']
    password = request.form['password']

 
    if session['method'] == 'register':
        if 'first_name' in request.form:
            session['first_name'] = first_name = request.form['first_name']
        if 'last_name' in request.form:
            session['last_name'] = last_name = request.form['last_name']
        if 'confirm_pw' in request.form:
            confirm_pw = request.form['confirm_pw']

        if len(first_name) < 1:
            flash("First name cannot be blank!", 'red')
            valid = False
        elif len(first_name) >= 1 and len(first_name) < 2:
            flash("First name must have 2 letters!", 'red')
            valid = False
        elif not NAME_REGEX.match(first_name):
            flash("Name can only contain letters!", 'red')
            valid = False
        else:
            flash("hidden", "hidden")

        if len(last_name) < 1:
            flash("Last name cannot be blank!", 'red ')
            valid = False
        elif len(last_name) >= 1 and len(last_name) < 2:
            flash("Last name must have 2 letters!", 'red')
            valid = False
        elif not NAME_REGEX.match(last_name):
            flash("Name can only contain letters!", 'red')
            valid = False
        else:
            flash("hidden", "hidden")

        if len(email) < 1:
            flash("Email cannot be blank!", 'red')
            valid = False
        elif not EMAIL_REGEX.match(email):
            flash("Invalid Email Address!", 'red')
            valid = False
        else:
            flash("hidden", "hidden")

        if len(password) < 1:
            flash("Password cannot be blank!", 'red ')
            valid = False
        elif len(password) < 8:
            flash("Password must be at least 8 characters!", 'red ')
            valid = False
        elif not PW_REGEX.match(password):
            flash("Password is weak!", 'red')
            flash("What is a strong password?", 'message')
            valid = False
        elif (confirm_pw) and (confirm_pw != password):
            flash("hidden", "hidden")
            flash("Password doesn't match!", 'red')
            valid = False
        else:
            flash("hidden", "hidden")
    
    if valid:
        # Determine if email already exists in DB
        verifyQuery = "SELECT * FROM users where email = (:email)"
        data = {
                'email': email
            }
        exists = mysql.query_db(verifyQuery, data)

        # If email does not exist then add it to DB
        if(not exists):
            if session['method'] == 'register':
                
                insertQuery = "INSERT INTO users (first_name, last_name, email, password, salt, created_at, updated_at) VALUES (:first_name, :last_name, :email, :hashed_pw, :salt, NOW(), NOW())"

                salt = binascii.b2a_hex(os.urandom(15))

                data = {
                        'first_name': first_name,
                        'last_name': last_name,
                        'email': email,
                        'hashed_pw': md5.new(password + salt).hexdigest(),
                        'salt': salt
                    }
                
                session_id = mysql.query_db(insertQuery, data)

                session['session_id'] = session_id
                goto = '/theWall'
            else:
                flash("User ({}) does not exist, please register or log in with valid email address!".format(email), 'red error register')
                goto = '/register'
        else:
            if session['method'] == 'register':
                flash("User, ({}) already exist! Please log in or register with different email address!".format(email), 'red error')
                goto = '/login'
            else:
                password_hash = exists[0]['password']
                encrypted_password = md5.new(password + exists[0]['salt']).hexdigest()
                
                if password_hash == encrypted_password:
                    session['session_id'] = exists[0]['id']
                    goto = '/theWall'
                else:
                    flash("Error, password does not match password on file!.", 'red error no_match')

    return redirect(goto)

@app.route('/post_message', methods=['POST'])
def post_message():
    message_post = request.form['post_text']

    insertQuery = "INSERT INTO messages (user_id, message, created_at, updated_at) VALUES (:user_id, :message, NOW(), NOW())"

    data = {
            'user_id': session['session_id'],
            'message': message_post
        }
    
    mysql.query_db(insertQuery, data)

    return redirect('/theWall')

@app.route('/delete_message/<message_id>')
def delete_message(message_id):
    deleteQuery = "DELETE FROM messages WHERE id={}".format(message_id)
    mysql.query_db(deleteQuery)
    
    return redirect('/theWall')

@app.route('/post_comment', methods=['POST'])
def post_comment():
    comment_post = request.form['comment_text']
    message_id = request.form['message_id']

    insertQuery = "INSERT INTO comments (message_id, user_id, comment, created_at, updated_at) VALUES (:message_id, :user_id, :comment, NOW(), NOW())"

    data = {
            'message_id': message_id,
            'user_id': session['session_id'],
            'comment': comment_post
        }
    
    mysql.query_db(insertQuery, data)

    return redirect('/theWall')

@app.route('/login')
def login():
    if 'session_id' in session:
        return redirect('/theWall')
    else:
        session['method'] = 'login'
        header = 'Login'
        link = { 'href': "/register", 'text': 'Register' }
        displayItems = [ 'email', 'Email: ', 'password', 'Password: ' ]
        return render_template('index.html', header = header, link = link, display = displayItems)

@app.route('/register')
def register():
    if 'session_id' in session:
        return redirect('/theWall')
    else:
        session['method'] = 'register'
        header = 'Register'
        link = { 'href': "/login", 'text': 'Login' }
        displayItems = [ 'first_name', 'First Name: ', 'last_name', 'Last Name: ', 'email', 'Email: ', 'password', 'Password: ', 'confirm_pw', 'Confirm: ' ]
        return render_template('index.html', header = header, link = link, display = displayItems)

@app.route('/logout')
def logout():
    session['method'] = 'login'
    session.pop('session_id')
    return redirect('/'+session['method'])

app.run(debug=True)