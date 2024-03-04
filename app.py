import re
import os
import datetime

from flask import Flask, flash, redirect, render_template, request, session, jsonify, url_for
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from cryptography.fernet import Fernet
import sqlite3


app = Flask(__name__)
app.debug = True

def load_key():
    """
    Load the previously generated key
    """
    try:
        return open("secret.key", "rb").read()
    except IOError:
        return None

def generate_key():
    """
    Generates a key and save it into a file
    """
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

# Load the key
key = load_key()

# If the key does not exist, generate a new one
if not key:
    generate_key()
    key = load_key()

cipher = Fernet(key)


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)
 
def get_db_connection():
    if "user_id" not in session:
        session.clear()  # Clear the session if user_id is not present
    conn = sqlite3.connect("passwords.db")
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/", methods=["GET", "POST"])
def index():
    # Check if user is logged in
    if "user_id" in session:

        # If it's a POST request, it's likely a search query
        if request.method == "POST":
            if "search" in request.form:
                # Handling search functionality
                search_query = request.form.get("search")
                results = []

                db = get_db_connection()
                encrypted_results = db.execute("SELECT * FROM passwords WHERE user_id = ?", (session["user_id"],)).fetchall()

                for encrypted_row in encrypted_results:
                    decrypted_row = {}
                    decryption_successful = True

                    for field in ["id", "website", "username", "email", "password", "notes"]:
                        encrypted_data = encrypted_row[field]
                        if field == "id":
                            decrypted_row[field] = encrypted_data
                        elif encrypted_data is not None:
                            try:
                                decrypted_data = cipher.decrypt(encrypted_data).decode()
                                decrypted_row[field] = decrypted_data
                            except Exception as e:
                                decrypted_row[field] = f"Decryption Error: {str(e)}"
                                decryption_successful = False
                        else:
                            decrypted_row[field] = None

                    if decryption_successful:
                        results.append(decrypted_row)
                # Filter the decrypted results based on the search query
                filtered_results = [row for row in results if row and (
                    search_query.lower() in row["website"].lower() if row["website"] else False
                    or search_query.lower() in row["notes"].lower() if row["notes"] else False
                )]

                
                username = db.execute("SELECT username FROM users WHERE id = ?", (session["user_id"],)).fetchone()["username"]
            
                db.close()

                # Render the template with the search results
                return render_template("index.html", username=username, rows=filtered_results)

            elif "sort" in request.form:
                # Handling sorting functionality
                sort_field = request.form.get("sort")
                order_field = request.form.get("order")
                db = get_db_connection()
                query = f"SELECT * FROM passwords WHERE user_id = ? ORDER BY {sort_field} {order_field}"
                table = db.execute(query, (session["user_id"],)).fetchall()
                rows = []
                for item in table:
                    decrypted_row = {}
                    decryption_successful = True

                    for field in ["id", "website", "username", "email", "password", "notes"]:
                        encrypted_data = item[field]
                        if field == "id":
                            decrypted_row[field] = encrypted_data
                        elif encrypted_data is not None:
                            try:
                                decrypted_data = cipher.decrypt(encrypted_data).decode()
                                decrypted_row[field] = decrypted_data
                            except Exception as e:
                                decrypted_row[field] = f"Decryption Error: {str(e)}"
                                decryption_successful = False
                        else:
                            decrypted_row[field] = None

                    if decryption_successful:
                        rows.append(decrypted_row)

                # Get username from the database
                username = db.execute("SELECT username FROM users WHERE id = ?", (session["user_id"],)).fetchone()["username"]
                db.close()

                # Render the index page with the username and sorted rows
                return render_template("index.html", username=username, rows=rows)

        try:
            # If it's a regular GET request, fetch all rows
            db = get_db_connection()
            table = db.execute("SELECT * FROM passwords WHERE user_id = ?", (session["user_id"],))
            rows = []

            # Fetch all rows from the cursor
            table_rows = table.fetchall()

            for item in table_rows:
                decrypted_row = {}
                decryption_successful = True

                for field in ["id", "website", "username", "email", "password", "notes", "created_at"]:
                    encrypted_data = item[field]
                    if field == "id" or field == "user_id" or field == "created_at":   
                        decrypted_row[field] = encrypted_data
                    elif encrypted_data is not None:
                        try:
                            decrypted_data = cipher.decrypt(encrypted_data).decode()
                            decrypted_row[field] = decrypted_data
                        except Exception as e:
                            decrypted_row[field] = f"Decryption Error: {str(e)}"
                            decryption_successful = False
                    else:
                        decrypted_row[field] = None

                if decryption_successful:
                    rows.append(decrypted_row)
        finally:
            db.close()
        print(rows)
        # Get username from the database
        db = get_db_connection()
        username = db.execute("SELECT username FROM users WHERE id = ?", (session["user_id"],)).fetchone()["username"]
        db.close()

        # Render the index page with the username and rows
        return render_template("index.html", username=username, rows=rows)

    else:
        # Redirect to login page if user is not logged in
        return redirect(url_for("login"))

# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Ensure username and password were submitted
        username = request.form.get("username")
        password = request.form.get("password")
        pin = request.form.get("pin")
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

        if user and check_password_hash(user["password"], password):
            # Verify PIN
            pin_hash = user["pin_hash"]
            if pin_hash and check_password_hash(pin_hash, pin):
                # Store session variable indicating PIN is verified
                session["pin_verified"] = True
                # Store user ID in session
                session["user_id"] = user["id"]
                flash("Successfully logged in!", "success")
                return redirect(url_for("index"))
            else:
                flash("Invalid PIN", "error")
                return redirect(url_for("login"))
        else:
            flash("Invalid username and/or password", "error")
            return redirect(url_for("login"))
    else:
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
        # Check if username already exists
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
        
        # Set and check pin
        pin = request.form.get("pin")

        if not pin or len(pin) != 4:
            flash("Must enter 4 digit pin", "error")
            return redirect(url_for("register"))

        pin_hashed = generate_password_hash(pin)
        password_hashed = generate_password_hash(password)

        db = get_db_connection()
        db.execute("INSERT INTO users (username, password, pin_hash) VALUES (?, ?, ?)", (username, password_hashed, pin_hashed))
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

            # Ensure website and password are provided
            if not website:
                flash("Must enter a URL", "error")
                return redirect("/add")
            if not password:
                flash("Must enter a password", "error")
                return redirect("/add")

            # Encode and encrypt data
            encoded_website = website.encode()
            encoded_username = username.encode() if username else None
            encoded_email = email.encode() if email else None
            encoded_password = password.encode()
            encoded_notes = notes.encode() if notes else None

            try:
                encrypted_website = cipher.encrypt(encoded_website)
                encrypted_username = cipher.encrypt(encoded_username) if encoded_username else None
                encrypted_email = cipher.encrypt(encoded_email) if encoded_email else None
                encrypted_password = cipher.encrypt(encoded_password)
                encrypted_notes = cipher.encrypt(encoded_notes) if encoded_notes else None
            except Exception as e:
                flash(f"Error encrypting data: {e}", "error")
                return redirect("/add")

            # Insert encrypted data into the database
            try:
                db = get_db_connection()
                db.execute("INSERT INTO passwords (user_id, website, username, password, notes, email, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (session["user_id"], encrypted_website, encrypted_username, encrypted_password, encrypted_notes, encrypted_email, datetime.datetime.now()))
                db.commit()
            except Exception as e:
                flash(f"Error inserting data into database: {e}", "error")
                return redirect("/add")
            finally:
                db.close()

            flash("Password added successfully", "success")
            return redirect("/")
        
        else:
            db = get_db_connection()
            username = db.execute("SELECT username FROM users WHERE id = ?", (session["user_id"],)).fetchone()["username"]
            db.close()
            return render_template("add.html", username=username)

    else:
        redirect("/login")

@app.route("/verify_pin", methods=["POST"])
def verify_pin():
    # Extract PIN from the request data
    pin = request.json.get("pin")

    if not pin:
        return jsonify({"success": False, "message": "PIN is required."}), 400

    # Query database for user's PIN hash
    db = get_db_connection()
    user = db.execute("SELECT pin_hash FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    db.close()

    if not user:
        return jsonify({"success": False, "message": "User not found."}), 404

    # Check if the provided PIN matches the stored PIN hash
    pin_hash = user["pin_hash"]
    if check_password_hash(pin_hash, pin):
        # PIN is verified
        session["pin_verified"] = True  # Set pin_verified to True
        return jsonify({"success": True}), 200
    else:
        # PIN verification failed
        return jsonify({"success": False, "message": "Incorrect PIN."}), 401


@app.route("/edit/<int:password_id>", methods=["GET", "POST"])
def edit_password(password_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        # Handle form submission to update password
        # Extract form data
        website = request.form.get("website")
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        notes = request.form.get("notes")

        # Encrypt data
        encrypted_website = cipher.encrypt(website.encode()) if website else None
        encrypted_username = cipher.encrypt(username.encode()) if username else None
        encrypted_email = cipher.encrypt(email.encode()) if email else None
        encrypted_password = cipher.encrypt(password.encode()) if password else None
        encrypted_notes = cipher.encrypt(notes.encode()) if notes else None

        # Get password_id from the form
        form_password_id = request.form.get("password_id")

        # Ensure that the password_id from the URL matches the password_id from the form
        if int(form_password_id) != password_id:
            flash("Invalid password ID", "error")
            return redirect(url_for("index"))

        # Update database entry
        db = get_db_connection()
        db.execute("UPDATE passwords SET website = ?, username = ?, email = ?, password = ?, notes = ?, created_at = ? WHERE id = ? AND user_id = ?",
                   (encrypted_website, encrypted_username, encrypted_email, encrypted_password, encrypted_notes, datetime.datetime.now(), password_id, session["user_id"]))
        db.commit()
        db.close()

        flash("Password updated successfully", "success")
        return redirect(url_for("index"))
    else:
        # Retrieve existing password details
        db = get_db_connection()
        password_row = db.execute("SELECT * FROM passwords WHERE id = ? AND user_id = ?", (password_id, session["user_id"])).fetchone()
        db.close()

        if password_row:
            # Decrypt password details
            decrypted_row = {}
            for field in ["website", "username", "email", "password", "notes"]:
                encrypted_data = password_row[field]
                if encrypted_data is not None:
                    try:
                        decrypted_data = cipher.decrypt(encrypted_data).decode()
                        decrypted_row[field] = decrypted_data
                    except Exception as e:
                        # Handle decryption errors gracefully
                        decrypted_row[field] = f"Decryption Error: {str(e)}"
                else:
                    decrypted_row[field] = None

            db = get_db_connection()
            username = db.execute("SELECT username FROM users WHERE id = ?", (session["user_id"],)).fetchone()["username"]
            db.close()
            # Pass password_id to the template
            return render_template("edit.html", password=decrypted_row, password_id=password_id, username=username)
        else:
            flash("Password not found or unauthorized", "error")
            return redirect(url_for("index"))
        
@app.route("/delete", methods=["POST"])
def delete_passwords():
    if request.method == "POST":
        # Get the IDs of selected rows to delete
        selected_ids = request.form.getlist("select")

        if not selected_ids:
            flash("No rows selected for deletion")
            return redirect(url_for('index'))

        # Convert IDs to integers
        selected_ids = [int(id) for id in selected_ids]

        # Delete the selected rows from the database
        db = get_db_connection()
        for id in selected_ids:
            db.execute("DELETE FROM passwords WHERE id = ?", (id,))
        db.commit()
        db.close()

        flash("Selected rows deleted successfully")
        return redirect(url_for('index')
)

    flash("Method not allowed", 405)
    return redirect(url_for('index')
)

def update_account_details(user_id, username, password, pin):
    """Update the account details in the database.

    Args:
        user_id (int): The user's ID.
        username (str): The user's new username.
        password (str): The user's new password.
        pin (str): The user's new pin.

    Returns:
        bool: True if the account was updated successfully, False otherwise.
    """
    try:
        db = get_db_connection()
        db.execute("UPDATE users SET username = ?, password = ?, pin_hash = ? WHERE id = ?",
                   (username, generate_password_hash(password), generate_password_hash(pin), user_id))
        db.commit()
    except Exception as e:
        db.rollback()
        flash(f"An error occurred while updating account details: {e}", "error")
        return False
    finally:
        db.close()
    return True
 
@app.route("/account", methods=["GET", "POST"])
def account():
    """
    Handle the editing of user account details.

    This function validates the input data and updates the account details in the database if the input is valid.

    :return: If the update of account details is successful, return a success flash message and redirect the user to the index page.
             If the update fails, return an error flash message and redirect the user to the account page.
    """
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirm = request.form.get("confirmation")
        pin = request.form.get("pin")

        # Validate username
        if not username:
            flash("Username is required", "error")
            return redirect(url_for("account"))

        db = get_db_connection()
        existing_users = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchall()
        db.close()
        if len(existing_users) > 0:
            flash("Username is already taken", "error")
            return redirect(url_for("account"))

        # Validate password
        if not password:
            flash("Password is required", "error")
            return redirect(url_for("account"))
        if not confirm:
            flash("Password confirmation is required", "error")
            return redirect(url_for("account"))
        if len(password) < 8 or (not bool(re.search(r'[^\w\s]', password)) or not bool(re.search(r'\d', password))):
            flash("Password must be at least 8 characters long and include at least one number and one symbol", "error")
            return redirect(url_for("account"))
        if password != confirm:
            flash("Passwords do not match", "error")
            return redirect(url_for("account"))

        # Validate PIN
        if not pin:
            flash("PIN is required", "error")
            return redirect(url_for("account"))
        if len(pin) != 4 or not pin.isdigit():
            flash("Must enter a 4-digit PIN", "error")
            return redirect(url_for("account"))

        if update_account_details(session["user_id"], username, password, pin):
            flash("Account details updated successfully", "success")
            return redirect(url_for("index"))
        else:
            flash("Failed to update account details", "error")
            return redirect(url_for("account"))
    else:
        db = get_db_connection()
        username = db.execute("SELECT username FROM users WHERE id = ?", (session["user_id"],)).fetchone()["username"]
        db.close()

        return render_template("account.html", username=username)
    
@app.route("/account/delete", methods=["POST"])
def delete_account():
    if request.method == "POST":
        db = get_db_connection()
        db.execute("DELETE FROM passwords WHERE user_id = ?", (session["user_id"],))
        db.execute("DELETE FROM users WHERE id = ?", (session["user_id"],))
        db.commit()
        db.close()
        session.clear()
        flash("Account deleted successfully", "success")
        return redirect(url_for("login"))
    flash("Method not allowed", 405)
    return redirect(url_for("index"))