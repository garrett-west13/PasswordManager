import re

from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
import sqlite3


app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)
 
def get_db_connection():
    conn = sqlite3.connect("passwords.db")
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/")
def index():
    # Check if user is logged in
    if "user_id" in session:
        # Get username from the database
        db = get_db_connection()
        username = db.execute("SELECT username FROM users WHERE id = ?", (session["user_id"],)).fetchone()["username"]
        db.close()
        # Render the index page with the username
        return render_template("index.html", username=username)
    else:
        # Redirect to login page if user is not logged in
        return redirect(url_for("login"))



@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Ensure username and password were submitted
        username = request.form.get("username")
        password = request.form.get("password")
        if not username:
            flash("Must provide username", "error")
            return redirect(url_for("login"))
        elif not password:
            flash("Must provide password", "error")
            return redirect(url_for("login"))

        # Query database for username
        db = get_db_connection()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        db.close()

        # Ensure username exists and password is correct
        if not user or not check_password_hash(user["password"], password):
            flash("Invalid username and/or password", "error")
            return redirect(url_for("login"))

        # Remember which user has logged in
        session["user_id"] = user["id"]
        flash("Successfully signed in!", "success")

        # Redirect user to home page after setting flash messages
        return redirect(url_for("index"))
    
    else:
        # User reached route via GET
        return render_template("login.html")

@app.route("/logout")
def logout():
    """Log user out"""
    flash("Logged out", "info")
    session.clear()
    return redirect(url_for("login"))



@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Set and check for valid username
        username = request.form.get("username")
        if not username:
            flash("Must provide username", "error")
            return redirect(url_for("register"))

        db = get_db_connection()
        existing_user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        db.close()
        if existing_user:
            flash("Username is already taken", "error")
            return redirect(url_for("register"))

        # Set and check for valid password
        password = request.form.get("password")
        confirm = request.form.get("confirmation")
        if not password:
            flash("Must provide password", "error")
            return redirect(url_for("register"))

        if len(password) < 8 or (not bool(re.search(r'[^\w\s]', password)) or not bool(re.search(r'\d', password))):
            flash("Password must be at least 8 characters long and include at least one number and one symbol", "error")
            return redirect(url_for("register"))

        if not confirm:
            flash("Must confirm password", "error")
            return redirect(url_for("register"))
        elif confirm != password:
            flash("Passwords must match", "error")
            return redirect(url_for("register"))

        password_hashed = generate_password_hash(password)

        db = get_db_connection()
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", (username, password_hashed))
        db.commit()

        user_id = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        db.close()

        if user_id:
            session["user_id"] = user_id["id"]
            flash("Successfully registered!", "success")
            return redirect("/")
        else:
            flash("Failed to retrieve user ID", "error")
            return redirect(url_for("register"))

    else:
        return render_template("register.html")