"""
Flask backend for the Events Hub application.
Used in conjunction with the frontend to provide a full-stack application.
The frontend is a mobile application made for the COMP3130 Mobile Application Development Course.
Server should have basic security but is not intended for production use. Will only be active
during the course duration.

Created by: Kaister300
"""

import os
import logging
import secrets
import string
import base64
import datetime
from threading import Thread
from io import BytesIO
import requests

from dotenv import load_dotenv
from functools import wraps
from flask import Flask, render_template, request, Response, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from jsonschema import validate, ValidationError
from random_word import RandomWords
from PIL import Image
import structlog

from Models import User, UserTokens, Event, Reports, db

# Set up logger
structlog.stdlib.recreate_defaults(log_level=logging.INFO)
logger = structlog.get_logger("events-hub-backend")

# Load env variables from .env
# Mostly for local testing.
load_dotenv()

# App Environment Variables
HOSTNAME: str = os.getenv("HOSTNAME", "localhost")
PORT: int = int(os.getenv("PORT", "3000"))
ENABLE_UNSAFE_ADMIN: bool = os.getenv("ENABLE_UNSAFE_ADMIN", "False").lower() == "true"
logger.info(f"UNSAFE_ADMIN_STATUS: {ENABLE_UNSAFE_ADMIN}")

# Flask App Configuration
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///events-hub.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.template_folder = "templates"
app.secret_key = os.getenv("SECRET_KEY")
if not app.secret_key:
    logger.error(
        "No secret key found in environment variables. \
Please generate one using 'secrets.token_hex(16)' \
and as it to the .env file as 'SECRET_KEY'."
    )
    os._exit(1)

# Initialise the database
db.init_app(app)
with app.app_context():
    db.create_all()


def generate_admin_username():
    """Generates a random passphrase for the admin user."""
    r = RandomWords()
    username = "-".join([r.get_random_word() for _ in range(3)])
    logger.info(f"Generated admin username: {username}")
    return username


def generate_admin_password():
    """Generates a random password for the admin user."""
    pwd = "".join(
        secrets.choice(string.ascii_letters + string.punctuation + string.digits)
        for _ in range(12)
    )
    logger.info(f"Generated admin password: {pwd}")
    return pwd


# Admin username and password generated on runtime.
# New password generated on incorrect attempts.
ADMIN_DETAILS = {
    "username": generate_admin_username(),
    "password": generate_admin_password(),
    "incorrect_attempts": 0,
}

SUPPORTED_IMAGES = [
    "image/apng",
    "image/avif",
    "image/gif",
    "image/jpeg",
    "image/png",
    "image/svg+xml",
    "image/webp",
]

# Duplicated Literals. Here to satisfy the linter.
IMAGE_TAG = "data:image/"
INVALID_IMAGE_MESSAGE = "Invalid image format"
IMAGE_ERROR_MESSAGE = "Image error"
UNSUPPORTED_IMAGE_MESSAGE = "Unsupported image format"
LOGIN_INCORRECT_MESSAGE = "Login Incorrect"


def scan_image(base64_str: str) -> bool:
    """
    Scans the image for any malicious content.
    Uses sightengine API for scanning.
    """
    sightengine_url = "https://api.sightengine.com/1.0/check-workflow.json"
    params = {
        "workflow": os.getenv("SIGHTENGINE_PHOTO_WORKFLOW"),
        "api_user": os.getenv("SIGHTENGINE_USER"),
        "api_secret": os.getenv("SIGHTENGINE_SECRET"),
    }
    files = {"media": base64.b64decode(base64_str)}
    r = requests.post(sightengine_url, params=params, files=files, timeout=10)
    return process_image_scan(r.json())


def process_image_scan(results: dict) -> bool:
    """Sets the conditions for a safe image from sightengine API results."""
    logger.info(f"Image scan results: {results}")
    if results["status"] != "success":
        return False
    if results["summary"]["action"] == "reject":
        return False
    return True


def load_image(base64_str: str) -> Image:
    """Loads the image from the base64 string."""
    image = Image.open(BytesIO(base64.b64decode(base64_str)))
    return image


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
    logger.info(f"Text scan results: {results}")
    if results["status"] != "success":
        return False
    if "profanity" in results and results["profanity"]["matches"]:
        return False
    return True


@app.context_processor
def inject_admin_login():
    """Adds log in status to Jinja2 variables."""
    admin_logged_in = session.get("admin_token") is not None
    return {"admin_logged_in": admin_logged_in}

def api_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        logger.info("Hit API login required decorator")
        # Check token from header
        if not (auth_token := request.headers.get("Authorisation")):
            return {"error": "Unauthorised"}, 401

        # Check if token exists in the database
        if not (token_entry := UserTokens.query.filter_by(token=auth_token).first()):
            return {"error": "Unauthorised"}, 401

        # Check if user from token exists in the database
        # Remove token if user does not exist
        if not (user := User.query.filter_by(id=token_entry.user_id).first()):
            db.session.delete(token_entry)
            db.session.commit()
            return {"error": "Unauthorised"}, 401
        logger.info("Passed API login required decorator")
        return f(*args, **kwargs)
    return decorated_function

def get_token_entry(auth_token) -> UserTokens:
    token_entry = UserTokens.query.filter_by(token=auth_token).first()
    return token_entry

def get_user_entry(token_entry) -> User:
    user = User.query.filter_by(id=token_entry.user_id).first()
    return user

# Landing page for the website
@app.route("/")
def index():
    """Landing page for the website."""
    return render_template("index.html")


# ================== Admin Routes ==================
# Administrator page
@app.route("/admin", methods=["GET"])
def admin():
    """Admin page for the website."""
    return render_template("admin.html")


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    """Login logic for the admin page."""
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
        logger.exception("Admin login validation error")
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
            logger.warning(f"Incorrect attempt to cause admin password reset: {data}")
        return {"error": "Admin Login Incorrect"}, 400

    # Create/Regenerate admin token on successful login
    session["admin_token"] = secrets.token_hex(16)
    return Response(status=200, response="Admin Login Successful")


@app.route("/admin/logout", methods=["GET"])
def admin_logout():
    """Logs out the admin by deleting the token from the session."""
    session.pop("admin_token", None)
    return Response(status=200, response="Admin Logout Successful")


@app.route("/admin/users", methods=["GET"])
@app.route("/admin/users/<user_id>", methods=["GET"])
def admin_users(user_id=None):
    """Returns the users in the database. Can specify user by ID."""
    if user_id is None:
        users = [user.to_dict() for user in User.query.all()]
        return render_template("admin_pages/users.html", users=users)

    if "admin_token" not in session:
        return "Unauthorised", 401

    user = db.get_or_404(User, user_id)
    return jsonify(user.to_dict())


@app.route("/admin/create_user", methods=["GET", "POST"])
def create_user():
    """Creates a user in the database."""
    if request.method == "GET":
        return render_template("admin_pages/create_user.html")

    if "admin_token" not in session:
        return Response(status=401, response="Unauthorised")

    # Picture data is base64 encoded image data.
    user_schema = {
        "properties": {
            "id": {"type": "string"},
            "firstName": {"type": "string"},
            "lastName": {"type": "string"},
            "description": {"type": "string"},
            "password": {"type": "string"},
            "pictureData": {"type": "string"},
            "unsafeAdmin": {"type": "boolean"},
        },
        "required": [
            "id",
            "firstName",
            "lastName",
            "password",
            "description",
            "pictureData",
            "unsafeAdmin",
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

    # Validate picture data
    if data["pictureData"].startswith(IMAGE_TAG):
        data["pictureData"] = data["pictureData"].split(",")[1]
    try:
        img: Image = load_image(data["pictureData"])
    except Image.UnidentifiedImageError:
        logger.exception(IMAGE_ERROR_MESSAGE)
        return INVALID_IMAGE_MESSAGE, 400
    mimetype = img.get_format_mimetype()
    if mimetype not in SUPPORTED_IMAGES:
        return UNSUPPORTED_IMAGE_MESSAGE, 400

    # External scanning of the image and text
    if data["unsafeAdmin"] and not ENABLE_UNSAFE_ADMIN:
        return "Unsafe admin creation is disabled", 400
    if not data["unsafeAdmin"]:
        msg, status = user_scanning(data)
        if msg and status:
            return msg, status

    # Construct picture data
    data["pictureData"] = f"data:{mimetype};base64,{data['pictureData']}"

    # Create user. NOTE: Hash is 162 bytes long with the default method.
    password_hash = generate_password_hash(data["password"])
    user = User(
        id=data["id"],
        firstName=data["firstName"],
        lastName=data["lastName"],
        description=data["description"],
        profilePicture=str.encode(data["pictureData"]),
        joinedEvents=[],
        passwordHash=password_hash,
    )
    db.session.add(user)
    db.session.commit()
    return Response(status=200, response="User created successfully")


def user_validation(data: dict) -> tuple[str, int]:
    """Validates the user data before creating the user."""
    try:
        int(data["id"])
    except ValueError:
        return "User ID must be a number", 400
    if len(data["id"]) <= 6 or len(data["id"]) >= 16:
        return "User ID must be between 7 and 15 digits long", 400
    if len(data["password"]) < 8:
        return "Password must be at least 8 characters long", 400
    if len(data["firstName"]) > 50:
        return "First name must be less than 50 characters long", 400
    if len(data["lastName"]) > 50:
        return "Last name must be less than 50 characters long", 400
    if len(data["description"]) > 150:
        return "Description must be less than 150 characters long", 400
    if (len(data["pictureData"]) / 1024) / 1024 > 10:
        return "Picture must be less than 10MB", 400
    return "", 0


def user_scanning(data: dict) -> tuple[str, int]:
    """Scans the user data for inappropriate content before creating the user."""
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
                target=user_scanning_target,
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
    return "", 0


def user_scanning_target(
    scan_results: dict, data: dict, key: str, validation_func
) -> None:
    """Thread target function for user_scanning."""
    scan_results.update({key: validation_func(data[key])})


@app.route("/admin/events", methods=["GET"])
@app.route("/admin/events/<event_id>", methods=["GET"])
def admin_events(event_id=None):
    """Returns the events in the database. Can specify event by ID."""
    if event_id is None:
        events = [event.to_dict() for event in Event.query.all()]
        return render_template("admin_pages/events.html", events=events)

    if "admin_token" not in session:
        return "Unauthorised", 401

    event = db.get_or_404(Event, event_id)
    return jsonify(event.to_dict())


@app.route("/admin/event/<event_id>/view", methods=["GET"])
def admin_focused_event(event_id):
    """Returns HTML view of event with specified ID."""
    if "admin_token" not in session:
        return "Unauthorised", 401

    event = db.get_or_404(Event, event_id)
    return render_template("admin_pages/event_view.html", event=event.to_dict())


@app.route("/admin/event/<event_id>/delete", methods=["DELETE"])
def admin_delete_event(event_id):
    """Deletes event from server."""
    if "admin_token" not in session:
        return "Unauthorised", 401

    event = db.get_or_404(Event, event_id)
    db.session.delete(event)
    db.session.commit()
    return Response(status=200, response="Event deleted successfully")


@app.route("/admin/create_event", methods=["GET", "POST"])
def create_event():
    """Creates an event in the database."""
    if request.method == "GET":
        users = [user.to_dict() for user in User.query.all()]
        return render_template("admin_pages/create_event.html", users=users)

    if "admin_token" not in session:
        return Response(status=401, response="Unauthorised")

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
            "unsafeAdmin": {"type": "boolean"},
        },
        "required": [
            "name",
            "description",
            "dateStart",
            "dateEnd",
            "location",
            "bannerImage",
            "creator",
            "unsafeAdmin",
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

    # Validate picture data
    if data["bannerImage"].startswith(IMAGE_TAG):
        data["bannerImage"] = data["bannerImage"].split(",")[1]
    try:
        img: Image = load_image(data["bannerImage"])
    except Image.UnidentifiedImageError:
        logger.exception(IMAGE_ERROR_MESSAGE)
        return INVALID_IMAGE_MESSAGE, 400
    mimetype = img.get_format_mimetype()
    if mimetype not in SUPPORTED_IMAGES:
        return UNSUPPORTED_IMAGE_MESSAGE, 400

    # External scanning of the image and text
    if data["unsafeAdmin"] and not ENABLE_UNSAFE_ADMIN:
        return "Unsafe admin creation is disabled", 400
    if not data["unsafeAdmin"]:
        msg, status = event_scanning(data)
        if msg and status:
            return msg, status

    # Construct picture data
    data["bannerImage"] = f"data:{mimetype};base64,{data['bannerImage']}"

    # Create event
    event = Event(
        name=data["name"],
        description=data["description"],
        dateStart=data["dateStart"],
        dateEnd=data["dateEnd"],
        location=data["location"],
        bannerImage=str.encode(data["bannerImage"]),
        attendees=[data["creator"]],
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
            data["dateStart"], "%Y-%m-%dT%H:%M:%S.%f"
        )
        data["dateEnd"] = datetime.datetime.strptime(
            data["dateEnd"], "%Y-%m-%dT%H:%M:%S.%f"
        )
    except ValueError:
        return "Invalid date format", 400
    if data["dateStart"] > data["dateEnd"]:
        return "Event start date must be before end date", 400
    if (len(data["bannerImage"]) / 1024) / 1024 > 10:
        return "Banner image must be less than 10MB", 400
    return "", 0


def event_scanning(data: dict) -> tuple[str, int]:
    """
    Scans the event data for inappropriate content before creating the event.
    Can be skipped by setting the 'unsafeAdmin' field to True.
    """
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
                target=event_scanning_target,
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
    return "", 0


def event_scanning_target(
    scan_results: dict, data: dict, key: str, validation_func
) -> None:
    """Thread target function for event_scanning."""
    scan_results.update({key: validation_func(data[key])})


@app.route("/admin/reports", methods=["GET"])
@app.route("/admin/reports/<report_id>", methods=["GET"])
def admin_reports(report_id=None):
    """Returns the reports in the database. Can specify report by ID."""
    if report_id is None:
        reports = [report.to_dict() for report in Reports.query.all()]
        return render_template("admin_pages/reports.html", reports=reports)

    if "admin_token" not in session:
        return "Unauthorised", 401

    report = db.get_or_404(Reports, report_id)
    return jsonify(report.to_dict())


@app.route("/admin/report/<report_id>/delete", methods=["DELETE"])
def admin_delete_report(report_id):
    """Deletes report from server."""
    if "admin_token" not in session:
        return "Unauthorised", 401

    report = db.get_or_404(Reports, report_id)
    db.session.delete(report)
    db.session.commit()
    return Response(status=200, response="Report deleted successfully")


# ================== API Routes ==================
@app.route("/api/login", methods=["GET", "POST"])
def user_login():
    """Login logic for the user."""
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
    try:
        validate(data, login_schema)
    except ValidationError:
        logger.exception("Login validation error")
        # Not returning the actual error message for security reasons
        return {"error": LOGIN_INCORRECT_MESSAGE}, 400

    # Login user with password.
    user = db.get_or_404(User, data["id"])

    if len(data["password"]) < 8:
        return {"error": LOGIN_INCORRECT_MESSAGE}, 400

    if not check_password_hash(user.passwordHash, data["password"]):
        return {"error": LOGIN_INCORRECT_MESSAGE}, 400

    logger.info(f"User logged in: {user.id}")

    # Return token for user.
    token = UserTokens.query.filter_by(user_id=user.id).first()
    if not token:
        token = UserTokens(user_id=user.id, token=secrets.token_hex(64))
        db.session.add(token)
        db.session.commit()

    return token.to_dict(), 200


@app.route("/api/logout", methods=["POST"])
def user_logout():
    """Logs out the user by deleting the token from the database."""
    # Check token from header.
    auth_header = request.headers.get("Authorisation")
    if not auth_header:
        return {"error": "Provide a token in the header"}, 400

    token_entry = UserTokens.query.filter_by(token=auth_header).first()
    if not token_entry:
        return {"error": "Invalid token"}, 400

    db.session.delete(token_entry)
    db.session.commit()
    return Response(status=200, response="User logged out")


@app.route("/api/validate_token", methods=["POST"])
def validate_token():
    """Validates the token for the user."""
    # Check token from header.
    auth_header = request.headers.get("Authorisation")
    if not auth_header:
        return {"error": "Provide a token in the header"}, 400

    token_entry = UserTokens.query.filter_by(token=auth_header).first()
    if not token_entry:
        return {"error": "Invalid token"}, 400

    return Response(status=200, response="Token is valid")


@app.route("/api/users", methods=["GET"])
@app.route("/api/users/<user_id>", methods=["GET"])
def get_users_api(user_id=None):
    """Returns the users in the database. Can specify user by ID."""
    if user_id is None:
        users = [user.to_dict() for user in User.query.all()]
        return jsonify(users)

    user = db.get_or_404(User, user_id)

    token = request.headers.get("Authorisation")
    if token:
        token_entry = UserTokens.query.filter_by(token=token).first()
        if token_entry and token_entry.user_id == user.id:
            return jsonify(user.to_dict_authorised())

    return jsonify(user.to_dict())


@app.route("/api/events", methods=["GET"])
@app.route("/api/events/<event_id>", methods=["GET"])
def get_events_api(event_id=None):
    """Returns the events in the database. Can specify event by ID."""
    if event_id is None:
        events = [event.to_dict() for event in Event.query.all()]
        return jsonify(events)

    event = db.get_or_404(Event, event_id)
    return jsonify(event.to_dict())


@app.route("/api/events/<event_id>/attendees", methods=["GET"])
def get_event_attendees(event_id):
    """Returns the attendees of the event."""
    event = db.get_or_404(Event, event_id)
    return jsonify(event.attendees)


@app.route("/api/create_event", methods=["POST"])
@api_login_required
def create_event_api():
    """Creates an event in the database. Must be authenticated user."""

    # Validate request body
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
    
    token = request.headers.get("Authorisation")
    token_entry = get_token_entry(token)
    user = get_user_entry(token_entry)

    # Check if creator is holder of the token.
    if data["creator"] != user.id:
        return {"error": "Unauthorised"}, 401

    # Validate event data
    (msg, status) = event_validation(data)
    if msg and status:
        return {"error": msg}, status

    # Validate picture data
    if data["bannerImage"].startswith(IMAGE_TAG):
        data["bannerImage"] = data["bannerImage"].split(",")[1]
    try:
        img: Image = load_image(data["bannerImage"])
    except Image.UnidentifiedImageError:
        logger.exception(IMAGE_ERROR_MESSAGE)
        return {"error": INVALID_IMAGE_MESSAGE}, 400
    mimetype = img.get_format_mimetype()
    if mimetype not in SUPPORTED_IMAGES:
        return {"error": UNSUPPORTED_IMAGE_MESSAGE}, 400
    if getattr(img, "is_animated", False):
        return {"error": "Animated images are not supported"}, 400

    # External scanning of the image and text
    msg, status = event_scanning(data)
    if msg and status:
        return {"error": msg}, status

    # Construct picture data
    data["bannerImage"] = f"data:{mimetype};base64,{data['bannerImage']}"

    # Create event
    event = Event(
        name=data["name"],
        description=data["description"],
        dateStart=data["dateStart"],
        dateEnd=data["dateEnd"],
        location=data["location"],
        bannerImage=str.encode(data["bannerImage"]),
        attendees=[data["creator"]],
        creator=data["creator"],
    )
    db.session.add(event)
    db.session.commit()
    return {"event_id": event.id}, 200


@app.route("/api/events/<event_id>/edit", methods=["DELETE"])
@api_login_required
def edit_event_api(event_id=None):
    """Edits event on server."""

    # Validate request body
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

    token = request.headers.get("Authorisation")
    token_entry = get_token_entry(token)
    user = get_user_entry(token_entry)

    # Check if event exists
    if not (event := Event.query.filter_by(id=event_id).first()):
        return {"error": "Event does not exist"}, 404

    # Check if creator is holder of the token
    if token_entry.user_id != event.creator or data["creator"] != user.id:
        return {"error": "Unauthorised"}, 401

    # Validate event data
    (msg, status) = event_validation(data)
    if msg and status:
        return {"error": msg}, status

    # Validate picture data
    if data["bannerImage"].startswith(IMAGE_TAG):
        data["bannerImage"] = data["bannerImage"].split(",")[1]
    try:
        img: Image = load_image(data["bannerImage"])
    except Image.UnidentifiedImageError:
        logger.exception(IMAGE_ERROR_MESSAGE)
        return {"error": INVALID_IMAGE_MESSAGE}, 400
    mimetype = img.get_format_mimetype()
    if mimetype not in SUPPORTED_IMAGES:
        return {"error": UNSUPPORTED_IMAGE_MESSAGE}, 400
    if getattr(img, "is_animated", False):
        return {"error": "Animated images are not supported"}, 400

    # External scanning of the image and text
    msg, status = event_scanning(data)
    if msg and status:
        return {"error": msg}, status

    # Construct picture data
    data["bannerImage"] = f"data:{mimetype};base64,{data['bannerImage']}"

    # Edit event
    event.name = data["name"]
    event.description = data["description"]
    event.dateStart = data["dateStart"]
    event.dateEnd = data["dateEnd"]
    event.location = data["location"]
    event.bannerImage = str.encode(data["bannerImage"])
    db.session.commit()
    return {"event_id": event.id}, 200


@app.route("/api/events/<event_id>/delete", methods=["DELETE"])
@api_login_required
def delete_event_api(event_id=None):
    """Deletes event on server."""

    token = request.headers.get("Authorisation")
    token_entry = get_token_entry(token)
    if not token_entry:
        return {"error": "Unauthorised"}, 401
    user = User.query.filter_by(id=token_entry.user_id).first()
    if not user:
        return {"error": "Unauthorised"}, 401

    # Check if event exists
    if not (event := Event.query.filter_by(id=event_id).first()):
        return {"error": "Event does not exist"}, 404

    # Check if token holder is the creator of the event
    if token_entry.user_id != event.creator or user.id != event.creator:
        return {"error": "Unauthorised"}, 401

    # Delete event
    db.session.delete(event)
    db.session.commit()
    return {"event_id": event.id}, 200

@app.route("/api/events/<event_id>/join", methods=["POST"])
@api_login_required
def join_event_api(event_id):
    """Joins event on server."""

    token = request.headers.get("Authorisation")
    token_entry = get_token_entry(token)
    if not token_entry:
        return {"error": "Unauthorised"}, 401
    user = User.query.filter_by(id=token_entry.user_id).first()
    if not user:
        return {"error": "Unauthorised"}, 401

    # Check if event exists
    if not (event := Event.query.filter_by(id=event_id).first()):
        return {"error": "Event does not exist"}, 404

    # Check if user is already attending the event
    if user.id in event.attendees:
        return {"error": "User is already attending the event"}, 400

    # Join event
    attendees_list: list = event.attendees.copy()
    attendees_list.append(user.id)
    event.attendees = attendees_list
    db.session.commit()
    return {"event_id": event.id}, 200

@app.route("/api/events/<event_id>/leave", methods=["POST"])
@api_login_required
def leave_event_api(event_id):
    """Leaves event on server."""
    token = request.headers.get("Authorisation")
    token_entry = get_token_entry(token)
    if not token_entry:
        return {"error": "Unauthorised"}, 401
    
    user = User.query.filter_by(id=token_entry.user_id).first()
    if not user:
        return {"error": "Unauthorised"}, 401

    # Check if event exists
    if not (event := Event.query.filter_by(id=event_id).first()):
        return {"error": "Event does not exist"}, 404

    # Check if user is hosting the event
    if user.id == event.creator:
        return {"error": "User is hosting the event"}, 400

    # Check if user is attending the event
    if user.id not in event.attendees:
        return {"error": "User is not attending the event"}, 400

    # Leave event
    attendees_list: list = event.attendees.copy()
    attendees_list.remove(user.id)
    event.attendees = attendees_list
    db.session.commit()
    return {"event_id": event.id}, 200


@app.route("/api/events/<event_id>/report", methods=["POST"])
@api_login_required
def report_event_api(event_id=None):
    """Reports event on server."""
    token = request.headers.get("Authorisation")
    token_entry = get_token_entry(token)
    if not token_entry:
        return {"error": "Unauthorised"}, 401

    # Check if event exists
    if not (event := Event.query.filter_by(id=event_id).first()):
        return {"error": "Event does not exist"}, 404

    # Check if token holder is the creator of the event
    if token_entry.user_id == event.creator:
        return {"error": "Unauthorised"}, 401

    # Report event
    report = Reports(
        event_id=event_id,
        user_id=token_entry.user_id,
    )
    db.session.add(report)
    db.session.commit()
    return {"event_id": event.id}, 200


if __name__ == "__main__":
    app.run(HOSTNAME, PORT, debug=True)
