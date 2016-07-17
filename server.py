from flask import Flask, render_template, redirect, request, session, flash
from mysqlconnection import MySQLConnector
from flask.ext.bcrypt import Bcrypt
import re
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')

app = Flask(__name__)
bcrypt = Bcrypt(app)
mysql = MySQLConnector(app,'wall')
app.secret_key = "dhrtdgrdh5dyyjugkmyjfdrd!"

@app.route('/', methods=['GET'])
def index():
	if not session.has_key('display'):
		session['display'] = False
	return render_template("index.html", display=session['display'])

@app.route('/login', methods=['POST'])
def login():
	email = request.form['login_email']
	password = request.form['login_password']
	user_query = "SELECT * FROM users WHERE email = :email LIMIT 1"
	query_data = { 'email': email }
	user = mysql.query_db(user_query, query_data)
	if len(user) < 1:
		flash('<div class="error">invalid credentials</div>')
	elif bcrypt.check_password_hash(user[0]['pw_hash'], password):
		session['id'] = user[0]['id']
		print "your session id is:", session['id']
		return redirect('/wall')
	else:
		flash('<div class="error">invalid credentials</div>')
	return redirect('/')

@app.route('/register', methods=['POST'])
def submit():
	if len(request.form['first_name']) < 2 or len(request.form['last_name']) < 2:
		flash('<div class="error">name required</div>')
	elif not (request.form['first_name']).isalpha() or not (request.form['last_name']).isalpha() :
		flash('<div class="error">name is not valid!</div>')
	elif not EMAIL_REGEX.match(request.form['email']):
		flash('<div class="error">email is not valid!</div>')
	elif len(request.form['password']) < 8:
		flash('<div class="error">password too short</div>')
	elif request.form['password'] != request.form['password_conf']:
		flash('<div class="error">passwords do not match</div>')
	else:
		flash('<div class="success">successful registration!</div>')
		password = request.form['password']
		pw_hash = bcrypt.generate_password_hash(password)
		query = "INSERT INTO users (first_name, last_name, email, pw_hash, created_at, updated_at) VALUES (:first_name, :last_name, :email, :pw_hash, NOW(), NOW())"
		data = {
		'first_name': request.form['first_name'],
		'last_name': request.form['last_name'],
		'email': request.form['email'],
		'pw_hash': pw_hash
		}
		mysql.query_db(query, data)
		session['display'] = True
	return redirect('/')

@app.route('/post', methods=['POST'])
def post():
	if len(request.form['message']) > 0:
		text = request.form['message']
		query = "INSERT INTO messages (message, created_at, updated_at, users_id) VALUES ( :message, NOW(), NOW(), :users_id )"
		data = {
		'message': text,
		'users_id':session['id']
		}
		mysql.query_db(query, data)
		return redirect('/wall')

	else:
		return redirect('/wall')

@app.route('/wall', methods=['GET'])
def messages():
	print "session id is: ",session['id']
	
	name_and_message_query = "SELECT concat_ws(' ',first_name,last_name), users_id, messages.message, date_format(messages.created_at, '%M %D %Y') AS date, messages.created_at FROM users JOIN messages ON messages.users_id = users.id ORDER BY created_at DESC"
	name_and_message = mysql.query_db(name_and_message_query)
	for x in range(0,len(name_and_message)):
		flash('<div class="message"><h4>' +name_and_message[x]["concat_ws(' ',first_name,last_name)"]+ ' - ' +name_and_message[x]['date']+ '</h4><p>' +name_and_message[x]['message']+ '</p><hr></div>')
	return render_template('wall.html')






















@app.route('/logout')
def clear():
	session.clear()
	return redirect('/')



app.run(debug=True)