from flask_login import UserMixin
from datetime import datetime, timezone, timedelta
import jwt
import random
import string
import os
from werkzeug.utils import secure_filename
from PIL import Image
import io
from sqlalchemy.sql import func
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.dialects.postgresql import JSONB
from database import db
import math

class FriendRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, accepted, declined
    created_at = db.Column(db.DateTime, default=func.now())
    updated_at = db.Column(db.DateTime, default=func.now(), onupdate=func.now())

    # Add relationship to User model
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_requests')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_requests')

    def __repr__(self):
        return f'<FriendRequest {self.sender_id} -> {self.receiver_id} ({self.status})>'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    reset_token = db.Column(db.String(500), unique=True)
    reset_token_expiry = db.Column(db.DateTime)
    profile_picture = db.Column(db.String(200))
    bio = db.Column(db.Text)
    interests = db.Column(db.Text)
    location = db.Column(db.String(120))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    age = db.Column(db.Integer)
    looking_for = db.Column(db.String(50))
    activities = db.Column(db.Text)
    availability = db.Column(db.String(50))
    privacy_settings = db.Column(db.JSON, default={
        'location_visible': True,
        'interests_visible': True,
        'bio_visible': True,
        'age_visible': True,
        'activities_visible': True,
        'availability_visible': True
    })
    uploaded_files = db.Column(db.JSON, default=[])
    activity_images = db.Column(db.JSON, default=[])  # Store list of activity image URLs
    otp_code = db.Column(db.String(6))
    otp_expiry = db.Column(db.DateTime)
    last_active = db.Column(db.DateTime, default=func.now())

    # Relationships for friend suggestions
    sent_matches = db.relationship(
        'UserMatch',
        foreign_keys='UserMatch.user_id',
        backref='sender',
        lazy='dynamic'
    )
    received_matches = db.relationship(
        'UserMatch',
        foreign_keys='UserMatch.matched_user_id',
        backref='receiver',
        lazy='dynamic'
    )

    friends = db.relationship(
        'User', 
        secondary='friend_connection',
        primaryjoin=('User.id==friend_connection.c.user_id'),
        secondaryjoin=('User.id==friend_connection.c.friend_id'),
        lazy='dynamic'
    )


    def get_match_score(self, other_user):
        """Calculate match score with another user based on various factors"""
        score = 0

        # Location proximity score (if both users have location data)
        if self.latitude and self.longitude and other_user.latitude and other_user.longitude:
            distance = self._calculate_distance(
                self.latitude, self.longitude,
                other_user.latitude, other_user.longitude
            )
            # Convert distance to a 0-1 score (closer = higher score)
            location_score = max(0, 1 - (distance / 100))  # 100km as max distance
            score += location_score * 0.3  # 30% weight for location

        # Interest matching score
        if self.interests and other_user.interests:
            my_interests = set(self.interests.lower().split(','))
            their_interests = set(other_user.interests.lower().split(','))
            common_interests = len(my_interests.intersection(their_interests))
            total_interests = len(my_interests.union(their_interests))
            interest_score = common_interests / total_interests if total_interests > 0 else 0
            score += interest_score * 0.3  # 30% weight for interests

        # Activity preference matching
        if self.activities and other_user.activities:
            my_activities = set(self.activities.lower().split(','))
            their_activities = set(other_user.activities.lower().split(','))
            common_activities = len(my_activities.intersection(their_activities))
            total_activities = len(my_activities.union(their_activities))
            activity_score = common_activities / total_activities if total_activities > 0 else 0
            score += activity_score * 0.2  # 20% weight for activities

        # Availability matching
        if self.availability and other_user.availability:
            availability_score = 1.0 if self.availability == other_user.availability else 0.5
            score += availability_score * 0.2  # 20% weight for availability

        return round(score, 2)

    def _calculate_distance(self, lat1, lon1, lat2, lon2):
        """Calculate distance between two points using Haversine formula"""
        R = 6371  # Earth's radius in kilometers

        lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
        dlat = lat2 - lat1
        dlon = lon2 - lon1

        a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
        c = 2 * math.asin(math.sqrt(a))
        return R * c

    def get_friend_suggestions(self, limit=10, filters=None):
        """Get friend suggestions sorted by match score with optional filters"""
        query = User.query.filter(
            User.id != self.id
        )

        if filters:
            # Apply username/location search
            if filters.get('search'):
                search_term = f"%{filters['search']}%"
                query = query.filter(
                    db.or_(
                        User.username.ilike(search_term),
                        User.location.ilike(search_term)
                    )
                )

            # Apply age filter
            if filters.get('min_age'):
                query = query.filter(User.age >= filters['min_age'])
            if filters.get('max_age'):
                query = query.filter(User.age <= filters['max_age'])

            # Apply activity filter
            if filters.get('activity'):
                activity_term = f"%{filters['activity']}%"
                query = query.filter(User.activities.ilike(activity_term))

            # Apply interest filter
            if filters.get('interest'):
                interest_term = f"%{filters['interest']}%"
                query = query.filter(User.interests.ilike(interest_term))

            # Apply distance filter if coordinates are available
            if filters.get('max_distance') and self.latitude and self.longitude:
                # This is a simplified approach, for more accurate results 
                # we should use PostGIS or a proper geospatial query
                lat_range = filters['max_distance'] / 111  # roughly kilometers to degrees
                lng_range = filters['max_distance'] / (111 * math.cos(math.radians(self.latitude)))

                query = query.filter(
                    User.latitude.between(self.latitude - lat_range, self.latitude + lat_range),
                    User.longitude.between(self.longitude - lng_range, self.longitude + lng_range)
                )

        potential_friends = query.all()

        # Calculate scores for filtered matches
        scored_matches = [
            (user, self.get_match_score(user))
            for user in potential_friends
        ]

        # Sort by score and return top matches
        scored_matches.sort(key=lambda x: x[1], reverse=True)
        return scored_matches[:limit]

    # Update the relationship to avoid circular backref
    chat_groups = db.relationship(
        'ChatGroup',
        secondary='group_membership',
        primaryjoin='User.id==group_membership.c.user_id',
        secondaryjoin='ChatGroup.id==group_membership.c.group_id',
        lazy='dynamic'
    )
    notifications = db.relationship('Notification', backref='user', lazy='dynamic')

    def get_unread_messages_count(self):
        return Message.query.filter_by(recipient_id=self.id, is_read=False).count()

    def is_friend_with(self, user):
        """Check if the current user is friends with the given user"""
        return self.friends.filter_by(id=user.id).first() is not None

    def add_friend(self, user):
        """Add a user as friend"""
        if not self.is_friend_with(user):
            self.friends.append(user)
            user.friends.append(self)
            return True
        return False

    def remove_friend(self, user):
        """Remove a user from friends"""
        if self.is_friend_with(user):
            self.friends.remove(user)
            user.friends.remove(self)
            return True
        return False

class UserMatch(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    matched_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    match_score = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, accepted, rejected
    created_at = db.Column(db.DateTime, default=func.now())
    updated_at = db.Column(db.DateTime, default=func.now(), onupdate=func.now())

    def __repr__(self):
        return f'<UserMatch {self.user_id} -> {self.matched_user_id} ({self.match_score})>'

# Friend connection table for many-to-many relationship
friend_connection = db.Table('friend_connection',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('friend_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    media_url = db.Column(db.String(500))  # For storing media file URLs
    media_type = db.Column(db.String(50))  # 'image', 'video', or 'voice'
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=func.now())

    # Relationships
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref='received_messages')

    def __repr__(self):
        return f'<Message {self.id}: {self.sender_id} -> {self.recipient_id}>'

# Fix for the ChatGroup model - removing circular backref
class ChatGroup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=func.now())
    creator = db.relationship('User', foreign_keys=[created_by])

    settings = db.Column(JSONB, default={
        'allow_media': True,
        'max_members': 50
    })

    # Fix the relationship to avoid circular backref
    members = db.relationship(
        'User',
        secondary='group_membership',
        primaryjoin='ChatGroup.id==group_membership.c.group_id',
        secondaryjoin='User.id==group_membership.c.user_id',
        lazy='dynamic'
    )

    def __repr__(self):
        return f'<ChatGroup {self.name}>'

# Group membership association table
group_membership = db.Table('group_membership',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('group_id', db.Integer, db.ForeignKey('chat_group.id'), primary_key=True),
    db.Column('joined_at', db.DateTime, default=func.now())
)

class GroupMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('chat_group.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    media_url = db.Column(db.String(500))
    media_type = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=func.now())

    # Relationships
    group = db.relationship('ChatGroup', backref='messages')
    sender = db.relationship('User', backref='group_messages')


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    type = db.Column(db.String(50), nullable=False)  # 'message', 'friend_request', 'nearby_friend'
    content = db.Column(db.Text, nullable=False)
    related_id = db.Column(db.Integer)  # ID of related entity (message_id, friend_request_id, etc.)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=func.now())