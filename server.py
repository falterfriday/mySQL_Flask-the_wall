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
	print query_data
	print user
	if len(user) < 1:
		flash('<div class="error">invalid credentials</div>')
	elif bcrypt.check_password_hash(user[0]['pw_hash'], password):
		return render_template("wall.html")
	else:
		flash('<div class="error">invalid credentials</div>')
	return redirect('/')

@app.route('/process', methods=['POST'])
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



@app.route('/clear')
def clear():
	session.clear()
	return redirect('/')
app.run(debug=True)