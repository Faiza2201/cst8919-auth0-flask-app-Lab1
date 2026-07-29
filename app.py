import json
import logging
from os import environ as env
from werkzeug.middleware.proxy_fix import ProxyFix
from urllib.parse import quote_plus, urlencode
from datetime import datetime

from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, render_template, session, url_for, request

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.secret_key = env.get("APP_SECRET_KEY")

# --- Logging setup ---
logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

oauth = OAuth(app)
oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={"scope": "openid profile email"},
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration',
)


@app.route("/")
def home():
    return render_template(
        "home.html",
        session=session.get("user"),
        pretty=json.dumps(session.get("user"), indent=4),
    )


@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )


@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token

    userinfo = token.get("userinfo", {})
    app.logger.info(
        "LOGIN_SUCCESS user_id=%s email=%s timestamp=%s",
        userinfo.get("sub"),
        userinfo.get("email"),
        datetime.utcnow().isoformat(),
    )

    return redirect("/")


@app.route("/protected")
def protected():
    user = session.get("user")
    if not user:
        app.logger.warning(
            "UNAUTHORIZED_ACCESS path=/protected ip=%s timestamp=%s",
            request.remote_addr,
            datetime.utcnow().isoformat(),
        )
        return redirect(url_for("login"))

    userinfo = user.get("userinfo", {})
    app.logger.info(
        "PROTECTED_ACCESS user_id=%s email=%s timestamp=%s",
        userinfo.get("sub"),
        userinfo.get("email"),
        __import__("datetime").datetime.utcnow().isoformat(),
    )

    return f"<h1>Protected Page</h1><p>Hello, {userinfo.get('name', 'user')}! You are authenticated.</p>"


@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://"
        + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(env.get("PORT", 3000)))