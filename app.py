import re
import os

from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from cryptography.fernet import Fernet
import sqlite3

key = Fernet.generate_key()
key_str = key.decode()  # Convert bytes to string

app = Flask(__name__)

# Load the key from an environment variable
os.environ["SECRET_KEY"] = key_str

# If the environment variable is not set, generate a new key
key = os.getenv("SECRET_KEY")

# Convert string back to bytes
if not key:
    key_str = Fernet.generate_key().decode()  # Generate new key and decode to string
    os.environ["SECRET_KEY"] = key_str
    key = key_str.encode()  # Convert string back to bytes

cipher = Fernet(key)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)
 
def get_db_connection():
    conn = sqlite3.connect("passwords.db")
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/", methods=["GET", "POST"])
def index():
    # Check if user is logged in
    if "user_id" in session:

        db = get_db_connection()
        table = db.execute("SELECT * FROM passwords")
        db.close
        rows = []

        for item in table:
            rows.append({
                "website": cipher.decrypt(item["website"]).decode(),
                "username": cipher.decrypt(item["username"]).decode(),
                "email": cipher.decrypt(item["email"]).decode(),
                "password": cipher.decrypt(item["password"]).decode(),
                "notes": cipher.decrypt(item["notes"]).decode()
            })

        # Get username from the database
        db = get_db_connection()
        username = db.execute("SELECT username FROM users WHERE id = ?", (session["user_id"],)).fetchone()["username"]
        db.close()
        # Render the index page with the username
        return render_template("index.html", username=username, rows=rows)
    
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
        db.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password_hashed))
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
    
    # Add Passwords and other info
@app.route("/add", methods=["GET", "POST"])
def add():

    if "user_id" in session:    

        if request.method == "POST":

            website = request.form.get("website")
            username = request.form.get("username")
            email = request.form.get("email")
            password = request.form.get("password")
            notes = request.form.get("notes")
       
        # Make sure there is at least a website and passwordc
            if not website:
                flash("Must enter a url", "error")
                return redirect("/add")
            if not password:
                flash("Must enter a password", "error")
                return redirect("/add")

            # Encoded Data
            encoded_website = website.encode()
            encoded_username = username.encode()
            encoded_email = email.encode()
            encoded_password = password.encode()
            encoded_notes = notes.encode()
            # Encrypt Data
            encrypted_website = cipher.encrypt(encoded_website)
            encrypted_username = cipher.encrypt(encoded_username)
            encrypted_email = cipher.encrypt(encoded_email)
            encrypted_password = cipher.encrypt(encoded_password)
            encrypted_notes = cipher.encrypt(encoded_notes)

            db = get_db_connection()
            db.execute("INSERT INTO passwords (user_id, website, username, password, notes, email) VALUES (?, ?, ?, ?, ?, ?)", 
                      (session["user_id"], encrypted_website, encrypted_username, encrypted_password, encrypted_notes, encrypted_email))
            db.commit()
            db.close()
        
            flash("Password added successfully", "success")
            return redirect("/")
    

        else:
            db = get_db_connection()
            username = db.execute("SELECT username FROM users WHERE id = ?", (session["user_id"],)).fetchone()["username"]
            db.close()
            return render_template("add.html", username=username)
    else:
        return redirect("/login")
