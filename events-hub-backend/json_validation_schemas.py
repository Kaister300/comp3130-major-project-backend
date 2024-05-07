"""
Holds all schemas used for JSON validation in app.py.
Thrown into python file to easily import into code.
"""

ADMIN_LOGIN_SCHEMA = {
    "properties": {
        "username": {"type": "string"},
        "password": {"type": "string"},
    },
    "required": ["username", "password"],
}

ADMIN_USER_SCHEMA = {
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

ADMIN_EVENT_SCHEMA = {
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

API_LOGIN_SCHEMA = {
    "properties": {
        "id": {"type": "string"},
        "password": {"type": "string"},
    },
    "required": ["id", "password"],
}

API_EVENT_SCHEMA = {
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
