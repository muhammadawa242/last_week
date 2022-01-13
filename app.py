import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

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


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Update history table for current prices
    rows = db.execute('SELECT DISTINCT * FROM history WHERE user_id IN (?) ORDER BY symbol', session['user_id'])

    # Current price of the stock
    for row in rows:
        symbol_dict = lookup(row['symbol'])
        db.execute('Update history SET price == (?) WHERE symbol IN (?)', symbol_dict['price'], row['symbol'])

    rows = db.execute('SELECT DISTINCT * FROM history WHERE user_id IN (?) ORDER BY symbol', session['user_id'])

    # Shares grouped by Symbols of companies
    shares = db.execute('SELECT SUM(share) FROM shares WHERE user_id IN (?) GROUP BY symbol ORDER BY symbol', session['user_id'])

    cashDict = db.execute('SELECT cash FROM users WHERE id == (?)', session['user_id'])
    cash = cashDict[0]['cash']

    return render_template('index.html', rows=rows, shares=shares, zip=zip, cash=cash)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # via GET
    if request.method == "GET":
        return render_template("buy.html")

    # via POST
    else:
        # Request the current info from IEX about the 'symbol'
        symbol_dict = lookup(request.form.get('symbol'))

        # Verify correct usage
        if symbol_dict == None:
            return apology('Invalid symbol!')

        share = request.form.get('shares')

        # Check that desired shares are valid
        if share.isalpha():
            return apology('Invalid Shares',400)
        share = float(share)
        if not share.is_integer() or share < 1:
            return apology('Invalid Shares',400)

        # Total price of the stock
        price = share * symbol_dict['price']

        # Query the database for the cash available to the user
        cash = db.execute('SELECT cash FROM users WHERE id == (?)', session['user_id'])

        # Cash left after buying the stock
        cash_left = cash[0]['cash'] - price

        # Cash left should be enough to buy the desired stock
        if cash_left < 1:
            return apology('Cannot buy the stock!')

        # Update the cash of the user in the users table
        db.execute('UPDATE users SET cash = (?) WHERE id = (?)', cash_left, session['user_id'])

        # Store info in history table and shares table
        db.execute('INSERT INTO history (user_id, name, symbol, price) VALUES (?, ?, ?, ?)', session['user_id'], symbol_dict['name'], symbol_dict['symbol'], symbol_dict['price'])
        db.execute('INSERT INTO shares (user_id, symbol, share) VALUES (?, ?, ?)', session['user_id'], symbol_dict['symbol'], share)

        return redirect('/')


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    history = db.execute('SELECT * FROM shares WHERE user_id IN (?)', session['user_id'])
    return render_template("history.html", history=history)


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

    # For POST(after submission of form) lookup the current price of the product
    if request.method == "POST":
        symbol = request.form.get("symbol")
        symbol_dict = lookup(symbol)
        if symbol_dict == None:
            return apology("Invalid symbol!")

        return render_template("quoteinfo.html", symbol_dict=symbol_dict)

    # For GET request show the form
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Validate correct usage
        db_usernames = db.execute("SELECT username FROM users")
        if username in db_usernames:
            return apology("This username has already been taken!",400)
        if not username:
            return apology("Please enter your Username",400)
        if not password:
            return apology("Please enter your Password",400)
        if not confirmation == password:
            return apology("Your password didn't match!",400)

        # Hash the password
        hashed_pass = generate_password_hash(password)

        # Check for duplicate username in database
        users = db.execute('SELECT username FROM users')
        for user in users:
            if username == user['username']:
                return apology('Username not avilable!',400)

        # Store the users data into the database
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)",username, hashed_pass)
        return redirect("/")

    # If the user came to this route via GET request
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # via GET
    if request.method == "GET":
        data = db.execute('SELECT DISTINCT symbol FROM shares WHERE user_id IN (?) ORDER BY symbol', session['user_id'])
        return render_template("sell.html", data=data)

    else:
        # Request the current info from IEX about the 'symbol'
        symbol_dict = lookup(request.form.get('symbol'))

        # Verify correct usage
        if symbol_dict == None:
            return apology('Invalid symbol!')

        share = request.form.get('shares')

        # Check that desired shares are valid
        if share.isalpha():
            return apology('Invalid Shares',400)
        share = float(share)
        if not share.is_integer() or share < 1:
            return apology('Invalid Shares',400)

        shares = db.execute('SELECT SUM(share) FROM shares WHERE user_id IN (?) AND symbol == (?) GROUP BY symbol ORDER BY symbol', session['user_id'], symbol_dict['symbol'])
        if share > shares[0]['SUM(share)']:
            return apology("Out of stock!")

        # Total price of the stock
        price = share * symbol_dict['price']

        # Query the database for the cash available to the user
        cash = db.execute('SELECT cash FROM users WHERE id == (?)', session['user_id'])

        # Cash left after buying the stock
        cash_left = cash[0]['cash'] + price

        # Update the cash of the user in the users table
        db.execute('UPDATE users SET cash = (?) WHERE id = (?)', cash_left, session['user_id'])
        db.execute('INSERT INTO shares (user_id, symbol, share) VALUES (?, ?, ?)', session['user_id'], symbol_dict['symbol'], -share)
        return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
