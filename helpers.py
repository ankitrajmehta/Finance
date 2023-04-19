import json
from urllib.request import urlopen
import requests
from flask import redirect, render_template, request, session
from functools import wraps


def apology(message, code=400):
    """Render message as an apology to user."""
    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", top=code, bottom=escape(message)), code


def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/1.1.x/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


def lookup(symbol):
    """Look up quote for symbol."""

    # Contact API
    try:
        url = "https://financialmodelingprep.com/api/v3/company/profile/"+str(symbol)+ "?apikey=08b20b73c21fec93dbd9c8a7ce1f724f"
        response= urlopen(url)
        data=response.read().decode("utf-8")
        profile= json.loads(data)
    except requests.RequestException:
        return None

    # Parse response
    try:
        return {
            "name": profile["profile"]["companyName"],
            "price": float(profile["profile"]["price"]),
            "symbol": profile["symbol"]
        }
    except (KeyError, TypeError, ValueError):
        return None


def usd(value):
    """Format value as USD."""
    return f"${value:,.2f}"

