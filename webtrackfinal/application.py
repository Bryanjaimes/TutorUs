import os

from flask import Flask, render_template, session, request, flash, redirect
from flask_session import Session
from cs50 import SQL
from werkzeug.security import generate_password_hash, check_password_hash
from tempfile import mkdtemp

from helpers import apology, login_required

#configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

#Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

#Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

#Configure CS50 library to use SQL database
db = SQL("sqlite:///tutoring.db")

@app.route("/", methods=["GET", "POST"])
@login_required
def home():
    usertype = db.execute("SELECT * FROM users WHERE id = :user_id", user_id = session["user_id"])
    firstname = db.execute("SELECT firstname FROM users WHERE id = :user_id", user_id = session["user_id"])
    return render_template("studenthome.html", firstname = firstname[0]["firstname"], usertype = usertype[0]["usertype"])

@app.route("/register", methods = ["GET", "POST"])
def register():

    #User registering by submitting form
    if request.method == "POST":

        #Check if form was submitted correctly
        if not request.form.get("username"):
            return apology("Oops, must provide username", 400)
        elif not request.form.get("password"):
            return apology("Oops, must provide password", 400)
        elif not request.form.get("usertype"):
            return apology("Oops, must choose either 'tutor' or 'student' ", 400)
        elif not request.form.get("firstname"):
            return apology("Oops, must provide full name", 400)
        elif not request.form.get("lastname"):
            apology("Oops, must provide full name")
        elif not request.form.get("password") == request.form.get("confirmation"):
            return apology("Oops, password does not match confirmation", 400)

        #Hash the password and insert the new user into database
        hash = generate_password_hash(request.form.get("password"))

        new_user_id = db.execute("INSERT INTO users (username, hash, usertype, firstname, lastname) VALUES(:username, :hash, :usertype, :firstname, :lastname)", username = request.form.get("username"), hash = hash, usertype = request.form.get("usertype"), firstname = request.form.get("firstname"), lastname = request.form.get("lastname"))

        #Check to see if username is taken
        if not new_user_id:
            return apology("Oops, username is taken", 400)

        #Remember which user is signed in
        session["user_id"] = new_user_id

        #Display flash message
        flash("Registered!")

        username = db.execute("SELECT username FROM users WHERE id = :user_id", user_id = session["user_id"])
        #Redirect user to home page
        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/login", methods = ["GET", "POST"])
def login():

    #Forget any user_id
    session.clear()

    #User reached route via POST (submitted form via POST)
    if request.method == "POST":

        #Ensure username was submitted
        if not request.form.get("username"):
            return apology("Oops, must provide username", 400)

        #Ensure password was submitted
        elif not request.form.get("password"):
            return apology("Oops, must provide password", 400)

        #Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username", username = request.form.get("username"))

        #Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 400)

        session["user_id"] = rows[0]["id"]

        return redirect("/")
    else:
        return render_template("login.html")

@app.route("/logout")
def logout():

    #Forget current user_id
    session.clear()

    #Redirect user to login
    return redirect("/login")

@app.route("/findtutor")
@login_required
def findtutor():

    if request.method == "GET":
        tutors = db.execute("SELECT * FROM users WHERE usertype = :usertype", usertype = 'tutor')
        user = db.execute("SELECT * FROM users WHERE id = :user_id", user_id = session["user_id"])
        return render_template("findtutor.html", tutors = tutors, usertype = user[0]["usertype"])
    else:
        redirect("/")

@app.route("/myaccount")
@login_required
def myaccount():

    if request.method == "GET":
        user = db.execute("SELECT * FROM users WHERE id = :user_id", user_id = session["user_id"])
        return render_template("myaccount.html", user = user)
    else:
        return redirect("/")
