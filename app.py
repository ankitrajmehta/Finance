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

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
#if not os.environ.get("API_KEY"):
 #   raise RuntimeError("API_KEY not set")


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
    quantity_stock = db.execute(
        "SELECT symbol, SUM(quantity) share_num FROM transactions WHERE user_id = ? GROUP BY symbol", session["user_id"])
    for one_stock in quantity_stock:
        store = lookup(one_stock["symbol"])
        cur_price = store["price"]
        total = cur_price * one_stock["share_num"]

        tmp = db.execute("SELECT * FROM portfolio WHERE user_id = ? AND symbol = ?", session["user_id"], one_stock["symbol"])
        if not tmp:
            db.execute("INSERT INTO portfolio (user_id, symbol, quantity, current_price, total) VALUES (?, ?, ?, ?, ?)",
                        session["user_id"], one_stock["symbol"], one_stock["share_num"], cur_price, total)
        else:
            db.execute("UPDATE portfolio SET quantity = ?, current_price = ?, total=? WHERE user_id = ? AND symbol = ?",
                       one_stock["share_num"], cur_price, total, session["user_id"], one_stock["symbol"])

    db.execute("DELETE FROM portfolio WHERE quantity = 0")
    cash_tmp = db.execute("Select cash FROM users WHERE id = ?", session["user_id"])
    cash_available = cash_tmp[0]["cash"]
    user_stock = db.execute("SELECT * FROM portfolio WHERE user_id = ?", session["user_id"])
    total_db = db.execute("SELECT SUM(total) total FROM portfolio WHERE user_id = ?", session["user_id"])
    total = total_db[0]["total"]
    return render_template("index.html", user_stock=user_stock, cash=cash_available, total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        if not request.form.get("symbol"):
            flash("Please Enter A Symbol")
            return redirect("/buy")
        if not request.form.get("shares"):
            flash("Please Enter Number Of Shares You Want To Purchase")
            return redirect("/buy")

        symbol = request.form.get("symbol")
        symbol = symbol.upper()
        shares = int(request.form.get("shares"))

        if shares < 1:
            flash("Number Of Shares Must Be Greater Than Zero")
            return redirect("/buy")

        info = lookup(symbol)
        if not info:
            flash("Symbol Not Found")
            return redirect("/buy")

        # find amt of cash in account
        cash_tmp = db.execute("Select cash FROM users WHERE id = ?", session["user_id"])
        cash_available = cash_tmp[0]["cash"]
        if cash_available < (info["price"] * shares):
            flash(f"Not Enough Funds To Buy {shares} shares of {symbol}")
            return redirect("/buy")

        # insert details of transactions into transactions table
        time = datetime.now()
        db.execute("INSERT INTO transactions (user_id, symbol, type, price, quantity, date) VALUES (?, ?, ?, ?, ?, ?)",
                    session["user_id"], symbol, "buy", info["price"], shares, time)
        cash_available = cash_available - (info["price"] * shares)
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash_available, session["user_id"])
        flash(f"{shares} shares of {symbol} Bought")
        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute("SELECT * FROM transactions WHERE user_id = ?", session["user_id"])

    return render_template("history.html", transactions=transactions)


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
@login_required
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
        if not request.form.get("symbol"):
            return redirect("/quote")
        info = lookup(request.form.get("symbol"))
        if not info:
            flash("Symbol Not Found")
            return redirect("/quote")

        return render_template("quoted.html", name=info["name"], price=info["price"], symbol=info["symbol"])
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password") or not request.form.get("confirmation"):
            return apology("must provide password", 400)

        elif not request.form.get("password") == request.form.get("confirmation"):
            return apology("passwords don't match", 400)

        # check if username is available
        same_user = db.execute("SELECT username FROM users WHERE username = ?", request.form.get("username"))
        if len(same_user) > 0:
            return apology("username not available ", 400)

        # insert into the database table users
        hashed = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", request.form.get("username"), hashed)

        # log in registered user
        current_user = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        session["user_id"] = current_user[0]["id"]

        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        if not request.form.get("symbol"):
            flash("Please Enter A Symbol")
            return redirect("/sell")
        if not request.form.get("shares"):
            flash("Please Enter Number Of Shares You Want To Sell")
            return redirect("/sell")

        symbol = request.form.get("symbol")
        symbol = symbol.upper()
        shares = int(request.form.get("shares"))
        check = db.execute("SELECT * FROM portfolio WHERE symbol = ? AND user_id = ?", symbol, session["user_id"])
        if len(check) < 1:
            flash("Stock Not In Portfolio")
            return redirect("/sell")

        if shares < 1:
            flash("Number Of Shares Must Be Greater Than Zero")
            return redirect("/sell")

        if shares > check[0]["quantity"]:
            flash(f"You don't have {shares} shares of {symbol} in your account ")
            return redirect("/sell")

        info = lookup(symbol)
        if not info:
            flash("Symbol Not Found")
            return redirect("/sell")

        # find amt of cash in account
        cash_tmp = db.execute("Select cash FROM users WHERE id = ?", session["user_id"])
        cash_available = cash_tmp[0]["cash"]

        # insert details of transactions into transactions table
        time = datetime.now()
        db.execute("INSERT INTO transactions (user_id, symbol, type, price, quantity, date) VALUES (?, ?, ?, ?, ?, ?)",
                   session["user_id"], symbol.upper(), "sell", info["price"], -shares, time)
        cash_available = cash_available + (info["price"] * shares)
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash_available, session["user_id"])
        flash(f"{shares} shares of {symbol} Sold")
        return redirect("/")
    else:
        symbol = db.execute("SELECT symbol FROM portfolio WHERE user_id = ?", session["user_id"])
        return render_template("sell.html", symbol=symbol)


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    """change password"""

    if request.method == "POST":

        # Ensure password was submitted
        if not request.form.get("new_password") or not request.form.get("confirm_password"):
            return apology("must provide password", 403)

        elif not request.form.get("new_password") == request.form.get("confirm_password"):
            return apology("passwords don't match", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])

        # Ensure password is correct
        if not check_password_hash(rows[0]["hash"], request.form.get("password")):
            flash("Invalid present password")
            return redirect("/settings")

        # insert into the database table users

        hashed = generate_password_hash(request.form.get("new_password"), method='pbkdf2:sha256', salt_length=8)
        db.execute("UPDATE users SET hash = ? WHERE id = ?", hashed, session["user_id"])
        flash("Password changed successfully")
        return redirect("/")

    else:
        return render_template("settings.html")


# export API_KEY=pk_7b717f08266148e2884fa96c7251db0c