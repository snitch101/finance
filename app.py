import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    buys = db.execute("SELECT * FROM buys WHERE user_id=?", session["user_id"])
    name
    return render_template("index.html", buys=buys)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        # Check for symbol using lookup
        valid_symbol = lookup(request.form.get("symbol"))
        cash_avail = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        # Ensure validity of symbol entered
        if not request.form.get("symbol") or not valid_symbol:
            return apology("Enter a valid symbol", 403)
        if not request.form.get("shares") or not int(request.form.get("shares")) or int(request.form.get("shares")) < 1:
            return apology("Enter valid share amount", 403)

        total_price = valid_symbol["price"] * int(request.form.get("shares"))
        if cash_avail[0]["cash"] < total_price:
            return apology("Not enough cash available", 300)

        current_date = datetime.utcnow()
        db.execute("INSERT INTO buys (user_id, stock_symbol, shares, share_price, price, date) VALUES (?, ?, ?, ?, ?, ?)", session["user_id"], request.form.get("symbol"), request.form.get("shares"), valid_symbol["price"], total_price, current_date)
        return redirect("/buy")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    return apology("TODO")


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

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
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
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":

        # Ensure symbol is not null
        if not request.form.get("symbol"):
            return apology("Symbol can not be null", 403)

        #Return values from lookup and ensure that it is not null
        values = lookup(request.form.get("symbol"))
        if not values:
            return apology("Symbol does not exist", 403)

        # Display lookup values
        return render_template("quoted.html", name=values["name"], price=values["price"], symbol=values["symbol"])


    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")

        # Ensure username was submitted
        if not username:
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Ensure confirmation was submitted
        elif not request.form.get("confirmation"):
            return apology("confirm password", 403)

        # Ensure username does not exist in database
        valid_username = db.execute("SELECT username FROM users WHERE username = ?", username)

        if valid_username:
            return apology("Username already exists", 403)

        # Ensure passwords match
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("Passwords do not match")

        password_hash = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, password_hash)

        return redirect("/login")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    return apology("TODO")
