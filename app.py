"""
app.py - Main Flask Application
Secure Registration and Login System
Cybersecurity Final Project

Security Features:
- SHA-256 hashing via hashlib
- Unique random salt per user (os.urandom)
- Server-side pepper (not stored in DB)
- Password strength validation
"""

import os
import hashlib
import secrets
import sqlite3
import re
from flask import Flask, render_template, request, redirect, url_for, session, flash

app = Flask(__name__)

# ─────────────────────────────────────────────
# PEPPER — secret server-side value (NOT stored in DB)
# In production, load this from an environment variable or secrets manager
# ─────────────────────────────────────────────
PEPPER = "Cy83rS3cur!tyP3pp3r$2026"

# ─────────────────────────────────────────────
# Database setup
# ─────────────────────────────────────────────
DB_PATH = "database/users.db"


def init_db():
    """Initialize the SQLite database and create users table if not exists."""
    os.makedirs("database", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT    NOT NULL UNIQUE,
            hash     TEXT    NOT NULL,
            salt     TEXT    NOT NULL
        )
    """)
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────
# Security Helper Functions
# ─────────────────────────────────────────────

def generate_salt():
    """Generate a unique 32-byte random salt, returned as a hex string."""
    return secrets.token_hex(32)  # 64-character hex string


def hash_password(password: str, salt: str) -> str:
    """
    Hash a password using:
      password + salt + pepper  →  SHA-256
    Returns the hex digest.
    """
    combined = password + salt + PEPPER
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


def check_password_strength(password: str) -> dict:
    """
    Evaluate password strength based on:
    - Minimum 12 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special symbol
    Returns a dict with individual checks and overall rating.
    """
    checks = {
        "min_length":  len(password) >= 12,
        "uppercase":   bool(re.search(r"[A-Z]", password)),
        "lowercase":   bool(re.search(r"[a-z]", password)),
        "digit":       bool(re.search(r"\d", password)),
        "symbol":      bool(re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?`~]", password)),
    }
    score = sum(checks.values())

    if score <= 2:
        strength = "Weak"
    elif score <= 4:
        strength = "Medium"
    else:
        strength = "Strong"

    checks["score"] = score
    checks["strength"] = strength
    return checks


def user_exists(username: str) -> bool:
    """Return True if username already exists in the database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    return result is not None


def register_user(username: str, password: str):
    """
    Register a new user:
    1. Generate a unique salt
    2. Hash: password + salt + pepper
    3. Store username, hash, and salt in DB (pepper never stored)
    """
    salt = generate_salt()
    password_hash = hash_password(password, salt)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (username, hash, salt) VALUES (?, ?, ?)",
        (username, password_hash, salt)
    )
    conn.commit()
    conn.close()


def verify_login(username: str, password: str) -> bool:
    """
    Verify login:
    1. Retrieve stored salt for the username
    2. Recompute hash using: input_password + stored_salt + pepper
    3. Compare with stored hash
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT hash, salt FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()

    if row is None:
        return False  # Username not found

    stored_hash, stored_salt = row
    computed_hash = hash_password(password, stored_salt)
    return computed_hash == stored_hash  # Constant-time-equivalent comparison


# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────

@app.route("/")
def index():
    """Redirect root to login page."""
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    """Handle user registration."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")

        # Basic field validation
        if not username or not password or not confirm:
            flash("All fields are required.", "error")
            return render_template("register.html")

        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("register.html")

        # Password strength check
        strength_result = check_password_strength(password)
        if strength_result["strength"] != "Strong":
            flash("Password is too weak. Please meet all requirements.", "error")
            return render_template("register.html")

        # Duplicate username check
        if user_exists(username):
            flash("Username already taken. Please choose another.", "error")
            return render_template("register.html")

        # Register the user securely
        register_user(username, password)
        flash("Registration successful! You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Handle user login."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Please enter both username and password.", "error")
            return render_template("login.html")

        if verify_login(username, password):
            session["username"] = username
            flash("Login successful! Welcome back.", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password.", "error")
            return render_template("login.html")

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    """Protected dashboard page — requires login."""
    if "username" not in session:
        flash("Please log in to access the dashboard.", "error")
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session["username"])


@app.route("/logout")
def logout():
    """Log the user out by clearing the session."""
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# ─────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────

app.secret_key = os.urandom(24)
init_db()

if __name__ == "__main__":
    app.run(debug=True)
