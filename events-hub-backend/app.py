import os
import logging
import secrets
import string
import base64
import datetime
from threading import Thread
import requests

from flask import Flask, render_template, request, Response, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import escape, escape_silent, Markup
from jsonschema import validate, ValidationError
from random_word import RandomWords

from Models import User, Event, db

logger = logging.getLogger("events-hub-backend")
logging.basicConfig(level=logging.INFO)

HOSTNAME = os.getenv("HOSTNAME", "localhost")
PORT = int(os.getenv("PORT", "3000"))

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///events-hub.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.template_folder = "templates"
app.secret_key = os.getenv("SECRET_KEY")
if not app.secret_key:
    app.secret_key = secrets.token_hex(16)

db.init_app(app)
with app.app_context():
    db.create_all()


def generate_admin_username():
    """Generates a random passphrase for the admin user."""
    r = RandomWords()
    username = "-".join([r.get_random_word() for _ in range(3)])
    logger.info("Generated admin username: %s", username)
    return username


def generate_admin_password():
    """Generates a random password for the admin user."""
    pwd = "".join(
        secrets.choice(string.ascii_letters + string.punctuation + string.digits)
        for _ in range(12)
    )
    logger.info("Generated admin password: %s", pwd)
    return pwd


# Admin username and password generated on runtime.
# New password generated on incorrect attempts.
ADMIN_DETAILS = {
    "username": generate_admin_username(),
    "password": generate_admin_password(),
    "incorrect_attempts": 0,
}


def scan_image(base64_uri: str) -> bool:
    """
    Scans the image for any malicious content.
    Uses sightengine API for scanning.
    """
    base64_uri = base64_uri.split(",")[1]
    sightengine_url = "https://api.sightengine.com/1.0/check.json"
    params = {
        "models": "nudity-2.0,wad,offensive,text-content,gore,text,qr-content",
        "api_user": os.getenv("SIGHTENGINE_USER"),
        "api_secret": os.getenv("SIGHTENGINE_SECRET"),
    }
    files = {"media": base64.b64decode(base64_uri)}
    r = requests.post(sightengine_url, params=params, files=files, timeout=10)
    return process_image_scan(r.json())


def process_image_scan(results: dict) -> bool:
    """Sets the conditions for a safe image from sightengine API results."""
    logging.info("Image scan results: %s", results)
    if results["status"] != "success":
        return False
    if results["nudity"]["none"] < 0.95:
        return False
    if results["weapon"] > 0.5:
        return False
    if results["alcohol"] > 0.5:
        return False
    if results["drugs"] > 0.5:
        return False
    if results["offensive"]["prob"] > 0.1:
        return False
    if results["gore"]["prob"] > 0.1:
        return False
    if results["text"]["profanity"]:
        return False
    if results["qr"]["profanity"]:
        return False
    if results["qr"]["blacklist"]:
        return False
    return True


def scan_text(data: str):
    """
    Scans the text for any malicious content.
    Uses sightengine API for scanning.
    """
    sightengine_url = "https://api.sightengine.com/1.0/text/check.json"
    params = {
        "lang": "en",
        "mode": "standard",
        "api_user": os.getenv("SIGHTENGINE_USER"),
        "api_secret": os.getenv("SIGHTENGINE_SECRET"),
    }
    data = {"text": data}
    r = requests.post(sightengine_url, params=params, data=data, timeout=10)
    return process_text_scan(r.json())


def process_text_scan(results: dict) -> bool:
    """Sets the conditions for a safe text from sightengine API results."""
    logging.info("Text scan results: %s", results)
    if results["status"] != "success":
        return False
    if "profanity" in results and results["profanity"]["matches"]:
        return False
    return True


@app.context_processor
def inject_admin_login():
    admin_logged_in = session.get("admin_token") is not None
    return {"admin_logged_in": admin_logged_in}


# Landing page for the website
@app.route("/")
def index():
    return render_template("index.html")


# ================== Admin Routes ==================
# Administrator page
@app.route("/admin", methods=["GET"])
def admin():
    return render_template("admin.html")


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "GET":
        return render_template("admin_pages/login.html")

    # Handle login requets
    login_schema = {
        "properties": {
            "username": {"type": "string"},
            "password": {"type": "string"},
        },
        "required": ["username", "password"],
    }
    data = request.json
    try:
        validate(data, login_schema)
    except ValidationError:
        logging.exception("Admin login validation error")
        # Not returning the actual error message for security reasons
        return {"error": "Admin Login Incorrect"}, 400

    if (
        data["username"] != ADMIN_DETAILS["username"]
        or data["password"] != ADMIN_DETAILS["password"]
    ):
        ADMIN_DETAILS["incorrect_attempts"] += 1
        if ADMIN_DETAILS["incorrect_attempts"] >= 3:
            ADMIN_DETAILS["password"] = generate_admin_password()
            ADMIN_DETAILS["incorrect_attempts"] = 0
            logging.warning("Incorrect attempt to cause admin password reset: %s", data)
        return {"error": "Admin Login Incorrect"}, 400

    # Create/Regenerate admin token on successful login
    session["admin_token"] = secrets.token_hex(16)
    return Response(status=200, response="Admin Login Successful")


@app.route("/admin/logout", methods=["GET"])
def admin_logout():
    session.pop("admin_token", None)
    return Response(status=200, response="Admin Logout Successful")


@app.route("/admin/users", methods=["GET"])
@app.route("/admin/users/<user_id>", methods=["GET"])
def admin_users(user_id=None):
    if user_id is None:
        users = [user.to_dict() for user in User.query.all()]
        return render_template("admin_pages/users.html", users=users)

    user = db.get_or_404(User, user_id)
    return jsonify(user.to_dict())


@app.route("/admin/create_user", methods=["GET", "POST"])
def create_user():
    if request.method == "GET":
        return render_template("admin_pages/create_user.html")

    if "admin_token" not in session:
        return Response(status=401, response="Unauthorized")

    # Picture data is base64 encoded image data.
    user_schema = {
        "properties": {
            "id": {"type": "string"},
            "firstName": {"type": "string"},
            "lastName": {"type": "string"},
            "description": {"type": "string"},
            "password": {"type": "string"},
            "pictureData": {"type": "string"},
        },
        "required": [
            "id",
            "firstName",
            "lastName",
            "password",
            "description",
            "pictureData",
        ],
    }
    data = request.json
    try:
        validate(data, user_schema)
    except ValidationError as e:
        return {"error": e.message}, 400
    # Database Field Validation
    (msg, status) = user_validation(data)
    if msg and status:
        return msg, status
    password_hash = generate_password_hash(data["password"]).split("$")[-1]
    user = User(
        id=data["id"],
        firstName=str(escape_silent(data["firstName"])),
        lastName=str(escape_silent(data["lastName"])),
        description=str(escape_silent(data["description"])),
        profilePicture=str.encode(data["pictureData"]),
        joinedEvents=[],
        passwordHash=password_hash,
    )
    db.session.add(user)
    db.session.commit()
    return Response(status=200, response="User created successfully")


def user_validation(data: dict) -> tuple[dict, int]:
    """Validates the user data before creating the user."""
    try:
        int(data["id"])
    except ValueError:
        return {"error": "User ID must be a number"}, 400
    if len(data["id"]) <= 6 or len(data["id"]) >= 16:
        return {"error": "User ID must be between 7 and 15 digits long"}, 400
    if len(data["password"]) < 8:
        return {"error": "Password must be at least 8 characters long"}, 400
    if len(data["firstName"]) > 50:
        return {"error": "First name must be less than 50 characters long"}, 400
    if len(data["lastName"]) > 50:
        return {"error": "Last name must be less than 50 characters long"}, 400
    if len(data["description"]) > 150:
        return {"error": "Description must be less than 150 characters long"}, 400
    if not data["pictureData"].startswith("data:image/"):
        return {"error": "Picture data must be an image"}, 400
    if (len(data["pictureData"]) / 1024) / 1024 > 10:
        return {"error": "Picture must be less than 10MB"}, 400
    scan_results = {
        "firstName": None,
        "lastName": None,
        "description": None,
        "pictureData": None,
    }
    threads: list[Thread] = []
    for key in scan_results:
        if key == "pictureData":
            validation_func = scan_image
        else:
            validation_func = scan_text
        threads.append(
            Thread(
                target=user_validation_target,
                args=(
                    scan_results,
                    data,
                    key,
                    validation_func,
                ),
            )
        )
        threads[-1].start()
    for thread in threads:
        thread.join()
    for key, value in scan_results.items():
        if not value:
            return {"error": f"{key} contains inappropriate content"}, 400
    return {}, 0


def user_validation_target(
    scan_results: dict, data: dict, key: str, validation_func
) -> None:
    """Thread target function for user_validation."""
    logging.info(scan_results)
    scan_results.update({key: validation_func(data[key])})


@app.route("/admin/events", methods=["GET"])
@app.route("/admin/events/<event_id>", methods=["GET"])
def admin_events(event_id=None):
    if event_id is None:
        events = [event.to_dict() for event in Event.query.all()]
        return render_template("admin_pages/events.html", events=events)

    if "admin_token" not in session:
        return "Unauthorized", 401

    event = db.get_or_404(Event, event_id)
    return jsonify(event.to_dict())


@app.route("/admin/create_event", methods=["GET", "POST"])
def create_event():
    if request.method == "GET":
        users = [user.to_dict() for user in User.query.all()]
        return render_template("admin_pages/create_event.html", users=users)

    if "admin_token" not in session:
        return Response(status=401, response="Unauthorized")

    event_schema = {
        "properties": {
            "name": {"type": "string"},
            "description": {"type": "string"},
            "dateStart": {"type": "string"},
            "dateEnd": {"type": "string"},
            "location": {
                "type": "object",
                "properties": {
                    "room": {"type": "string"},
                    "address": {"type": "string"},
                },
            },
            "bannerImage": {"type": "string"},
            "creator": {"type": "string"},
        },
        "required": [
            "name",
            "description",
            "dateStart",
            "dateEnd",
            "location",
            "bannerImage",
            "creator",
        ],
    }
    data = request.json
    try:
        validate(data, event_schema)
    except ValidationError as e:
        return {"error": e.message}, 400

    # Database Field Validation
    (msg, status) = event_validation(data)
    if msg and status:
        return msg, status
    event = Event(
        name=str(escape_silent(data["name"])),
        description=str(escape_silent(data["description"])),
        dateStart=data["dateStart"],
        dateEnd=data["dateEnd"],
        location=data["location"],
        bannerImage=str.encode(data["bannerImage"]),
        creator=data["creator"],
    )
    db.session.add(event)
    db.session.commit()
    return Response(status=200, response="Event created successfully")


def event_validation(data) -> tuple[str, int]:
    """Validates the event data before creating the event."""
    if User.query.filter_by(id=data["creator"]).first() is None:
        return "Creator ID does not exist", 400
    if len(data["name"]) > 100:
        return "Event name must be less than 100 characters long", 400
    if len(data["description"]) > 500:
        return "Event description must be less than 500 characters long", 400
    try:
        data["dateStart"] = datetime.datetime.strptime(
            data["dateStart"], "%Y-%m-%dT%H:%M"
        )
        data["dateEnd"] = datetime.datetime.strptime(data["dateEnd"], "%Y-%m-%dT%H:%M")
    except ValueError:
        return "Invalid date format", 400
    if data["dateStart"] > data["dateEnd"]:
        return "Event start date must be before end date", 400
    if not data["bannerImage"].startswith("data:image/"):
        return "Banner image data must be an image", 400
    if (len(data["bannerImage"]) / 1024) / 1024 > 10:
        return "Banner image must be less than 10MB", 400
    scan_results = {
        "name": None,
        "description": None,
        "location": None,
        "bannerImage": None,
    }
    threads: list[Thread] = []
    for key in scan_results:
        if key == "bannerImage":
            validation_func = scan_image
        else:
            validation_func = scan_text
        threads.append(
            Thread(
                target=event_validation_target,
                args=(
                    scan_results,
                    data,
                    key,
                    validation_func,
                ),
            )
        )
        threads[-1].start()
    for thread in threads:
        thread.join()
    for key, value in scan_results.items():
        if not value:
            return f"{key} contains inappropriate content", 400
    return {}, 0


def event_validation_target(
    scan_results: dict, data: dict, key: str, validation_func
) -> None:
    """Thread target function for event_validation."""
    scan_results.update({key: validation_func(data[key])})


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
    user = db.get_or_404(User, data["id"])

    if len(data["password"]) < 8:
        return {"error": "Login Incorrect"}, 400

    if not check_password_hash(user.passwordHash, data["password"]):
        return {"error": "Login Incorrect"}, 400

    return {"token": "token"}, 200


@app.route("/api/users", methods=["GET"])
@app.route("/api/users/<user_id>", methods=["GET"])
def get_users_api(user_id=None):
    if user_id is None:
        users = [user.to_dict() for user in User.query.all()]
        return jsonify(users)

    user = db.get_or_404(User, user_id)
    return jsonify(user.to_dict())


@app.route("/api/events", methods=["GET"])
@app.route("/api/events/<event_id>", methods=["GET"])
def get_events_api(event_id=None):
    if event_id is None:
        events = [event.to_dict() for event in Event.query.all()]
        return jsonify(events)

    event = db.get_or_404(Event, event_id)
    return jsonify(event.to_dict())


if __name__ == "__main__":
    app.run(HOSTNAME, PORT, debug=True)
