import os
import re

from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
import sqlite3


app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

def get_db_connection():
    conn = sqlite3.connect('passwords.db')
    conn.row_factory = sqlite3.Row
    return conn

# Function to initialize the database
def initialize_database():
    try:
        conn = sqlite3.connect('passwords.db')
        with app.open_resource('schema.sql', mode='r') as f:
            conn.cursor().executescript(f.read())
        conn.commit()
    except Exception as e:
        print(f"An error occurred during database initialization: {e}")
    finally:
        if conn:
            conn.close()


# Call the initialization function when the application starts
@app.before_first_request
def before_first_request():
    initialize_database()


@app.route("/")
def index():
    # Check if user is logged in
    if "user_id" not in session:
        return redirect(url_for("login"))

    # Get username from the database
    db = get_db_connection()
    username = db.execute("SELECT username FROM users WHERE id = ?", (session["user_id"],)).fetchone()["username"]
    db.close()

    # Render the index page with the username
    return render_template("index.html", username=username)