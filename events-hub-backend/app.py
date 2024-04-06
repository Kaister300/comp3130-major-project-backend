import os
import logging
from flask import Flask, render_template, request, Response
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import escape, escape_silent, Markup
from jsonschema import validate, ValidationError

from Models import User, Event, db

logger = logging.getLogger(__name__)

HOSTNAME = os.getenv("HOSTNAME", "localhost")
PORT = int(os.getenv("PORT", "3000"))


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///events-hub.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.template_folder = "templates"

db.init_app(app)
with app.app_context():
    db.create_all()


# Landing page for the website
@app.route("/")
def index():
    return render_template("index.html")


# ================== Admin Routes ==================
# Administrator page
@app.route("/admin")
def admin():
    # TODO: Add authentication logic here
    return render_template("admin.html")


@app.route("/admin/create_user", methods=["GET", "POST"])
def create_user():
    if request.method == "GET":
        return render_template("create_user.html")

    user_schema = {
        "properties": {
            "id": {"type": "string"},
            "firstName": {"type": "string"},
            "lastName": {"type": "string"},
            "password": {"type": "string"},
            "pictureData": {"type": "string"},
        },
        "required": ["id", "firstName", "lastName", "password", "pictureData"],
    }
    data = request.json
    try:
        validate(data, user_schema)
    except ValidationError as e:
        return {"error": e.message}, 400
    # TODO: Add user creation logic here
    return Response(status=200, response="User created successfully")


# ================== API Routes ==================
@app.route("/api/login", methods=["GET", "POST"])
def user_login():
    # Return webpage for webview in app
    if request.method == "GET":
        return render_template("login.html")

    # Handle login requets
    login_schema = {
        "properties": {
            "id": {"type": "string"},
            "password": {"type": "string"},
        },
        "required": ["id", "password"],
    }

    data = request.json
    logger.info("Login request: %s", data)
    try:
        validate(data, login_schema)
    except ValidationError:
        logging.exception("Login validation error")
        # Not returning the actual error message for security reasons
        return {"error": "Login Incorrect"}, 400
    # TODO: Add login logic here
    if len(data["password"]) < 8:
        return {"error": "Login Incorrect"}, 400

    return {"token": "token"}, 200


if __name__ == "__main__":
    app.run(HOSTNAME, PORT, debug=True)
