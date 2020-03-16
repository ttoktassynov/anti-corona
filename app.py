import os
import feedparser
import sqlite3
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response



# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)



# Make sure API key is set
#if not os.environ.get("API_KEY"):
#    raise RuntimeError("API_KEY not set")


@app.route("/")
#@login_required
def index():
    RSS_URLS = [
        'https://www.who.int/rss-feeds/news-english.xml',
        ]

    entries = []
    for url in RSS_URLS:
        entries.extend(feedparser.parse(url).entries)

    entries_sorted = sorted(
        entries,
        key=lambda e: e.published_parsed,
        reverse=True)

    return render_template(
        'index.html',
        entries=entries_sorted
        )
    return apology("TODO")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    return apology("TODO")

@app.route("/changePass", methods=["GET", "POST"])
@login_required
def changePass():
    """Change password"""
    uid = session["user_id"]
    if (request.method == "GET"):
        return render_template("changePass.html")
    else:
        oldPass = request.form.get("oldPass")
        newPass = request.form.get("newPass")
        newPassConf = request.form.get("newPassConf")
        # Validate inputs
        if not oldPass or not newPass or not newPassConf:
            return apology("Must provide passwords", 403)
        db = sqlite3.connect("corona.db")
        curObj = db.cursor()
        curObj.execute("SELECT hash FROM users where id=?", (uid,))
        rows = curObj.fetchall()
        if not check_password_hash(rows[0][0], oldPass):
            return apology("Old password incorrect", 403)
        if newPass != newPassConf:
            return apology("New password must match", 403)
        h = generate_password_hash(newPass)
        
        curObj.execute("UPDATE users SET hash=? where id=?", (h, uid,))
        db.commit()
        db.close()
        # Redirect user to home page
        flash("You successfully changed password!")
        return redirect("/")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        uname = request.form.get("username")
        db = sqlite3.connect('corona.db')
        # Query database for username
        curObj = db.cursor()
        curObj.execute("SELECT id, hash FROM users WHERE username = ?", (uname,))
        rows = curObj.fetchall()
        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0][1], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0][0]

        # Redirect user to home page
        flash("You successfully logged in!")
        db.close()
        return redirect("/")


    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    flash("You successfully logged out!")
    return redirect("/")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        username = request.form.get("username")
        if not username:
            return apology("must provide username", 403)
        else:
            db = sqlite3.connect('corona.db')
            curOjb = db.cursor()
            curOjb.execute("SELECT * FROM users WHERE username = ?",
                (username,))
            rows = curOjb.fetchall()
            if len(rows) == 1:
                return apology("username already exists", 403)

        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Ensure password was submitted
        if not password or not confirmation:
            return apology("must provide password", 403)
        elif password != confirmation:
            return apology("passwords must match", 403)

        curOjb.execute("INSERT INTO users (username, hash) values (?, ?)",
            (username, generate_password_hash(password),))
        flash("You successfully registered!")
        db.commit()
        db.close()
        return redirect("/")

    else:
        return render_template("register.html")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
