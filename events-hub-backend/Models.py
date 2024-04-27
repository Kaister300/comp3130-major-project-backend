"""
Module to hold the models for the database.
"""

import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


# Define User model
class User(db.Model):
    """Used to hold student information."""

    __tablename__ = "user"
    id = db.Column(db.String(15), primary_key=True, nullable=False)
    firstName = db.Column(db.String(50), nullable=False)
    lastName = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(150), nullable=False)
    profilePicture = db.Column(db.LargeBinary, nullable=False)
    joinedEvents = db.Column(db.JSON)
    passwordHash = db.Column(db.String(162), nullable=False)
    created = db.Column(db.DateTime, default=datetime.datetime.now, nullable=False)

    def to_dict(self) -> dict:
        """
        Returns a dictionary representation of the User object.
        Does not return the password hash or joinedEvents.
        """
        return {
            "id": self.id,
            "firstName": self.firstName,
            "lastName": self.lastName,
            "description": self.description,
            "profilePicture": self.profilePicture.decode(),
            "created": self.created,
        }

    def to_dict_authorised(self) -> dict:
        """
        Returns a dictionary representation of the User object.
        Does not return the password hash.
        """
        return {
            "id": self.id,
            "firstName": self.firstName,
            "lastName": self.lastName,
            "description": self.description,
            "profilePicture": self.profilePicture.decode(),
            "created": self.created,
            "joinedEvents": self.joinedEvents,
        }


class Event(db.Model):
    """Used to hold event information."""

    __tablename__ = "event"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    dateStart = db.Column(db.DateTime, nullable=False)
    dateEnd = db.Column(db.DateTime, nullable=False)
    location = db.Column(db.JSON, nullable=False)
    bannerImage = db.Column(db.LargeBinary, nullable=False)
    attendees = db.Column(db.JSON, nullable=False)
    creator = db.Column(db.String(15), db.ForeignKey("user.id"), nullable=False)

    def to_dict(self) -> dict:
        """Returns a dictionary representation of the Event object."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "dateStart": self.dateStart.strftime("%Y-%m-%d %H:%M:%S"),
            "dateEnd": self.dateEnd.strftime("%Y-%m-%d %H:%M:%S"),
            "location": self.location,
            "bannerImage": self.bannerImage.decode(),
            "attendees": self.attendees,
            "creator": self.creator,
        }


class UserTokens(db.Model):
    """Used to hold user tokens."""

    __tablename__ = "user_tokens"
    __table_args__ = (db.UniqueConstraint("user_id"),)
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.String(15), db.ForeignKey("user.id"), nullable=False, unique=True
    )
    token = db.Column(db.String(128), nullable=False)
    created = db.Column(db.DateTime, default=datetime.datetime.now, nullable=False)

    def to_dict(self) -> dict:
        """
        Returns a dictionary representation of the UserTokens object.
        SHOULD NEVER BE CALLED UNLESS SENDING TOKEN TO AUTHORISED USER.
        """
        return {
            "id": self.id,
            "user_id": self.user_id,
            "token": self.token,
            "created": self.created,
        }


class Reports(db.Model):
    """Used to hold reports on events."""

    __tablename__ = "reports"
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey("event.id"), nullable=False)
    user_id = db.Column(db.String(15), db.ForeignKey("user.id"), nullable=False)
    created = db.Column(db.DateTime, default=datetime.datetime.now, nullable=False)

    def to_dict(self) -> dict:
        """
        Returns a dictionary representation of the Reports object.
        """
        return {
            "id": self.id,
            "event_id": self.event_id,
            "user_id": self.user_id,
            "created": self.created,
        }
