from flask import Flask, render_template, flash, redirect, url_for, request, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from PIL import Image
import os
import logging
from datetime import datetime, timezone, timedelta
from oauthlib.oauth2 import WebApplicationClient
import random
import string
import io
from database import db
from models import User, UserMatch, FriendRequest, Message as DbMessage, ChatGroup, GroupMessage, Notification
from forms import LoginForm, RegistrationForm, RequestPasswordResetForm, ResetPasswordForm, ProfileForm
import json
from flask_socketio import SocketIO, emit, join_room, leave_room
import numpy as np
from math import radians, sin, cos, sqrt, atan2

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-12345')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize SocketIO with proper error handling
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    logger=True,
    engineio_logger=True,
    ping_timeout=60,
    ping_interval=25
)

# Mail configuration - simplified and explicit
mail_username = os.environ.get('MAIL_USERNAME')
mail_password = os.environ.get('MAIL_PASSWORD')
mail_sender = os.environ.get('MAIL_DEFAULT_SENDER')

logger.info(f"Mail Configuration - Username: {'Set' if mail_username else 'Not Set'}, "
           f"Password: {'Set' if mail_password else 'Not Set'}, "
           f"Sender: {'Set' if mail_sender else 'Not Set'}")

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = mail_username
app.config['MAIL_PASSWORD'] = mail_password
app.config['MAIL_DEFAULT_SENDER'] = mail_sender

# Initialize Flask-Mail with explicit app context
mail = Mail()
with app.app_context():
    mail.init_app(app)

def send_otp_email(user_email, otp):
    try:
        logger.info(f"Attempting to send OTP email to {user_email}")
        logger.debug(f"Mail config: SERVER={app.config['MAIL_SERVER']}, "
                    f"PORT={app.config['MAIL_PORT']}, "
                    f"TLS={app.config['MAIL_USE_TLS']}, "
                    f"USERNAME={'Set' if app.config['MAIL_USERNAME'] else 'Not Set'}")

        with app.app_context():
            msg = Message()
            msg.subject = "Your Login OTP"
            msg.sender = app.config['MAIL_DEFAULT_SENDER']
            msg.recipients = [user_email]
            msg.body = f'''Your OTP for login is: {otp}

This code will expire in 10 minutes.
If you did not request this code, please ignore this email.'''

            mail.send(msg)
            logger.info(f"OTP email sent successfully to {user_email}")
            return True
    except Exception as e:
        logger.error(f"Failed to send OTP email: {str(e)}")
        logger.error(f"Error type: {type(e)}")
        logger.error(f"Error args: {e.args}")
        return False

# Ensure upload directory exists
upload_dir = os.path.join('static', 'uploads')
os.makedirs(upload_dir, exist_ok=True)

# Add to the existing app configuration
UPLOAD_FOLDER = os.path.join('static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

@login_manager.user_loader
def load_user(user_id):
    logger.debug(f"Loading user with ID: {user_id}")
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    logger.info("Accessing login route")
    if current_user.is_authenticated:
        return redirect(url_for('profile'))

    form = LoginForm()
    if form.validate_on_submit():
        logger.debug(f"Attempting login for email: {form.email.data}")
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            logger.debug("User found, checking password")
            password_matches = check_password_hash(user.password_hash, form.password.data)
            logger.debug(f"Password check result: {password_matches}")
            if password_matches:
                # Generate and store OTP
                otp = ''.join(random.choices(string.digits, k=6))
                user.otp_code = otp
                user.otp_expiry = datetime.now(timezone.utc) + timedelta(minutes=10)

                # Send OTP via email
                if send_otp_email(user.email, otp):
                    db.session.commit()
                    return jsonify({"success": True, "message": "OTP sent successfully"})
                else:
                    return jsonify({"success": False, "message": "Failed to send OTP. Please try again."})
            else:
                logger.debug("Password verification failed")
        else:
            logger.debug("User not found")
        return jsonify({"success": False, "message": "Invalid email or password"})

    return render_template('login.html', form=form)

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    logger.info("Verifying OTP")
    email = request.form.get('email')
    otp = request.form.get('otp')

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"success": False, "message": "User not found"})

    if not user.otp_code or not user.otp_expiry:
        return jsonify({"success": False, "message": "No OTP request found"})

    # Convert otp_expiry to UTC if it's naive
    user_otp_expiry = user.otp_expiry
    if user_otp_expiry.tzinfo is None:
        user_otp_expiry = user_otp_expiry.replace(tzinfo=timezone.utc)

    if datetime.now(timezone.utc) > user_otp_expiry:
        return jsonify({"success": False, "message": "OTP has expired"})

    if user.otp_code != otp:
        return jsonify({"success": False, "message": "Invalid OTP"})

    login_user(user)
    user.otp_code = None
    user.otp_expiry = None
    db.session.commit()

    return jsonify({"success": True, "redirect": url_for('home')})

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/home')
@login_required
def home():
    # Pass current datetime for online status calculations
    now = datetime.now(timezone.utc)

    # Get all friends including newly accepted requests
    friends = current_user.friends.all()

    # Ensure all friend's last_active times are timezone-aware
    for friend in friends:
        if friend.last_active and friend.last_active.tzinfo is None:
            friend.last_active = friend.last_active.replace(tzinfo=timezone.utc)
        # Update friend's latitude/longitude if not set
        if not friend.latitude or not friend.longitude:
            friend.latitude = None
            friend.longitude = None

    db.session.commit()

    return render_template('home.html', now=now)

@app.route('/register', methods=['GET', 'POST'])
def register():
    logger.info("Accessing register route")
    if current_user.is_authenticated:
        return redirect(url_for('profile'))

    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data
        )
        user.password_hash = generate_password_hash(form.password.data)

        try:
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            logger.error(f"Registration error: {str(e)}")
            db.session.rollback()
            flash('An error occurred during registration.', 'danger')

    return render_template('register.html', form=form)

@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RequestPasswordResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            # Generate reset token
            token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
            user.reset_token = token
            user.reset_token_expiry = datetime.now(timezone.utc) + timedelta(hours=24)
            db.session.commit()
            # TODO: Send password reset email
            flash('Check your email for instructions to reset your password', 'info')
            return redirect(url_for('login'))
        flash('If an account exists with that email, password reset instructions will be sent.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_password_request.html', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user = User.query.filter_by(reset_token=token).first()
    if not user or not user.reset_token_expiry or datetime.now(timezone.utc) > user.reset_token_expiry:
        flash('Invalid or expired reset token', 'error')
        return redirect(url_for('login'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.password_hash = generate_password_hash(form.password.data)
        user.reset_token = None
        user.reset_token_expiry = None
        db.session.commit()
        flash('Your password has been reset.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)

@app.route('/')
def index():
    logger.info("Accessing index route")
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm()
    if form.validate_on_submit():
        try:
            # Handle profile picture upload
            if 'profile_picture' in request.files:
                file = request.files['profile_picture']
                if file and file.filename:
                    # Process image
                    image = Image.open(file)
                    # Resize image to 512x512
                    image = image.resize((512, 512))
                    # Convert to RGB if necessary
                    if image.mode != 'RGB':
                        image = image.convert('RGB')
                    # Save to bytes
                    img_byte_arr = io.BytesIO()
                    image.save(img_byte_arr, format='JPEG')
                    img_byte_arr = img_byte_arr.getvalue()

                    # Generate unique filename
                    filename = secure_filename(file.filename)
                    filepath = os.path.join('static', 'uploads', filename)

                    # Save processed image
                    with open(filepath, 'wb') as f:
                        f.write(img_byte_arr)

                    current_user.profile_picture = url_for('static', filename=f'uploads/{filename}')

            # Update user profile information
            current_user.bio = form.bio.data
            current_user.interests = form.interests.data
            current_user.location = form.location.data
            current_user.age = form.age.data
            current_user.looking_for = form.looking_for.data
            current_user.activities = form.activities.data
            current_user.availability = form.availability.data

            # Update privacy settings
            current_user.privacy_settings = {
                'location_visible': form.location_visible.data,
                'interests_visible': form.interests_visible.data,
                'bio_visible': form.bio_visible.data,
                'age_visible': form.age_visible.data,
                'activities_visible': form.activities_visible.data,
                'availability_visible': form.availability_visible.data
            }

            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile'))

        except Exception as e:
            app.logger.error(f"Profile update error: {str(e)}")
            flash('An error occurred while updating your profile.', 'danger')
            db.session.rollback()

    # Pre-populate form with current user data
    elif request.method == 'GET':
        form.bio.data = current_user.bio
        form.interests.data = current_user.interests
        form.location.data = current_user.location
        form.age.data = current_user.age
        form.looking_for.data = current_user.looking_for
        form.activities.data = current_user.activities
        form.availability.data = current_user.availability

        # Set privacy settings
        if current_user.privacy_settings:
            form.location_visible.data = current_user.privacy_settings.get('location_visible', True)
            form.interests_visible.data = current_user.privacy_settings.get('interests_visible', True)
            form.bio_visible.data = current_user.privacy_settings.get('bio_visible', True)
            form.age_visible.data = current_user.privacy_settings.get('age_visible', True)
            form.activities_visible.data = current_user.privacy_settings.get('activities_visible', True)
            form.availability_visible.data = current_user.privacy_settings.get('availability_visible', True)

    return render_template('profile.html', form=form)


@app.route('/friend-suggestions')
@login_required
def friend_suggestions():
    logger.info(f"Getting friend suggestions for user {current_user.id}")

    # Get filter parameters from request
    filters = {
        'search': request.args.get('search', ''),
        'min_age': request.args.get('min_age', type=int),
        'max_age': request.args.get('max_age', type=int),
        'activity': request.args.get('activity', ''),
        'interest': request.args.get('interest', ''),
        'max_distance': request.args.get('max_distance', type=float)
    }

    # Remove empty filters
    filters = {k: v for k, v in filters.items() if v}

    # Get potential matches (users who are not friends and not blocked)
    potential_matches = User.query.filter(
        User.id != current_user.id,
        ~User.id.in_([f.id for f in current_user.friends])
    ).all()

    # Calculate match scores and sort by compatibility
    matches = []
    for user in potential_matches:
        match_scores = calculate_match_score(current_user, user)

        # Apply filters
        if filters:
            if 'min_age' in filters and (not user.age or user.age < filters['min_age']):
                continue
            if 'max_age' in filters and (not user.age or user.age > filters['max_age']):
                continue
            if 'activity' in filters and (not user.activities or
                filters['activity'].lower() not in user.activities.lower()):
                continue
            if 'interest' in filters and (not user.interests or
                filters['interest'].lower() not in user.interests.lower()):
                continue
            if 'max_distance' in filters and match_scores['distance'] < 1 - (filters['max_distance'] / 50):
                continue

        matches.append({
            'user': user,
            'scores': match_scores
        })

    # Sort matches by total score
    matches.sort(key=lambda x: x['scores']['total'], reverse=True)

    # Update last active timestamp
    current_user.last_active = datetime.now(timezone.utc)
    db.session.commit()

    return render_template('friend_suggestions.html',
                         matches=matches[:10],  # Top 10 matches
                         current_filters=filters)

def calculate_distance(lat1, lon1, lat2, lon2):
    """Calculate the distance between two points using Haversine formula."""
    R = 6371  # Earth's radius in kilometers

    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1

    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * atan2(sqrt(a), sqrt(1-a))
    distance = R * c

    return distance

def calculate_activity_similarity(user1_activities, user2_activities):
    """Calculate similarity score between two users' activities."""
    if not user1_activities or not user2_activities:
        return 0.0

    # Convert activities to sets for comparison
    activities1 = set(user1_activities.lower().split(',')) if isinstance(user1_activities, str) else set()
    activities2 = set(user2_activities.lower().split(',')) if isinstance(user2_activities, str) else set()

    if not activities1 or not activities2:
        return 0.0

    # Calculate Jaccard similarity
    intersection = len(activities1.intersection(activities2))
    union = len(activities1.union(activities2))

    return intersection / union if union > 0 else 0.0

def calculate_availability_overlap(user1_availability, user2_availability):
    """Calculate overlap in users' availability."""
    if not user1_availability or not user2_availability:
        return 0.0

    avail1 = set(user1_availability.lower().split(',')) if isinstance(user1_availability, str) else set()
    avail2 = set(user2_availability.lower().split(',')) if isinstance(user2_availability, str) else set()

    if not avail1 or not avail2:
        return 0.0

    intersection = len(avail1.intersection(avail2))
    union = len(avail1.union(avail2))

    return intersection / union if union > 0 else 0.0

def calculate_match_score(user1, user2, max_distance=50):
    """Calculate overall match score between two users."""
    scores = {
        'distance': 0.0,
        'activity': 0.0,
        'availability': 0.0,
        'total': 0.0
    }

    # Calculate distance score if both users have location data
    if all([user1.latitude, user1.longitude, user2.latitude, user2.longitude]):
        distance = calculate_distance(user1.latitude, user1.longitude,
                                   user2.latitude, user2.longitude)
        # Convert distance to a score between 0 and 1
        scores['distance'] = max(0, 1 - (distance / max_distance))

    # Calculate activity similarity
    scores['activity'] = calculate_activity_similarity(user1.activities, user2.activities)

    # Calculate availability overlap
    scores['availability'] = calculate_availability_overlap(user1.availability, user2.availability)

    # Calculate total score with weighted components
    weights = {
        'distance': 0.4,
        'activity': 0.4,
        'availability': 0.2
    }

    scores['total'] = sum(score * weights[key] for key, score in scores.items() if key != 'total')

    return scores

@app.route('/send-friend-request/<int:user_id>', methods=['POST'])
@login_required
def send_friend_request(user_id):
    logger.info(f"Sending friend request from user {current_user.id} to user {user_id}")

    if user_id == current_user.id:
        flash('You cannot send a friend request to yourself.', 'error')
        return redirect(url_for('friend_suggestions'))

    # Check if request already exists
    existing_request = FriendRequest.query.filter_by(
        sender_id=current_user.id,
        receiver_id=user_id
    ).first()

    if existing_request:
        logger.info(f"Friend request already exists: {existing_request}")
        flash('Friend request already sent.', 'info')
        return redirect(url_for('friend_suggestions'))

    try:
        # Create new friend request
        friend_request = FriendRequest(sender_id=current_user.id, receiver_id=user_id)
        db.session.add(friend_request)
        logger.debug(f"Created friend request: {friend_request}")

        # Create notification for the receiver
        notification = Notification(
            user_id=user_id,
            type='friend_request',
            content=f'{current_user.username} sent you a friend request',
            related_id=friend_request.id
        )
        db.session.add(notification)
        logger.debug(f"Created notification: {notification.id} for user {user_id}")
        db.session.commit()
        logger.info("Successfully committed friend request and notification to database")

        # Emit socket event for real-time notification
        socket_data = {
            'type': 'friend_request',
            'content': f'{current_user.username} sent you a friend request',
            'sender': {
                'id': current_user.id,
                'username': current_user.username,
                'profile_picture': current_user.profile_picture
            }
        }
        logger.debug(f"Emitting socket.io event to room user_{user_id}: {socket_data}")
        socketio.emit('new_notification', socket_data, room=f'user_{user_id}')

        flash('Friend request sent successfully!', 'success')
        return redirect(url_for('friend_suggestions'))
    except Exception as e:
        logger.error(f"Error sending friend request: {str(e)}")
        db.session.rollback()
        flash('An error occurred while sending the friend request.', 'danger')
        return redirect(url_for('friend_suggestions'))

@app.route('/friend-requests')
@login_required
def friend_requests():
    received_requests = FriendRequest.query.filter_by(
        receiver_id=current_user.id,
        status='pending'
    ).all()
    return render_template('friend_requests.html', requests=received_requests)

@app.route('/handle-friend-request/<int:request_id>/<string:action>')
@login_required
def handle_friend_request(request_id, action):
    friend_request = FriendRequest.query.get_or_404(request_id)

    if friend_request.receiver_id != current_user.id:
        flash('Unauthorized action', 'danger')
        return redirect(url_for('friend_requests'))

    sender = User.query.get(friend_request.sender_id)
    if not sender:
        flash('User not found', 'danger')
        return redirect(url_for('friend_requests'))

    if action == 'accept':
        # Add both users to each other's friends list
        current_user.add_friend(sender)
        friend_request.status = 'accepted'

        # Create notification for the sender
        notification = Notification(
            user_id=sender.id,
            type='friend_request_accepted',
            content=f'{current_user.username} accepted your friend request',
            related_id=friend_request.id
        )
        db.session.add(notification)

        # Emit socket event for real-time notification
        socketio.emit('new_notification', {
            'type': 'friend_request_accepted',
            'content': f'{current_user.username} accepted your friend request',
            'sender': {
                'id': current_user.id,
                'username': current_user.username,
                'profile_picture': current_user.profile_picture
            }
        }, room=f'user_{sender.id}')

        flash('Friend request accepted!', 'success')
    elif action == 'decline':
        friend_request.status = 'declined'

        # Create notification for the sender
        notification = Notification(
            user_id=sender.id,
            type='friend_request_declined',
            content=f'{current_user.username} declined your friend request',
            related_id=friend_request.id
        )
        db.session.add(notification)

        # Emit socket event for real-time notification
        socketio.emit('new_notification', {
            'type': 'friend_request_declined',
            'content': f'{current_user.username} declined your friend request',
            'sender': {
                'id': current_user.id,
                'username': current_user.username,
                'profile_picture': current_user.profile_picture
            }
        }, room=f'user_{sender.id}')

        flash('Friend request declined.', 'info')
    else:
        flash('Invalid action', 'danger')
        return redirect(url_for('friend_requests'))

    db.session.commit()
    return redirect(url_for('friend_requests'))

@app.route('/my-friends')
@login_required
def my_friends():
    return render_template('friends.html', friends=current_user.friends)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload-activity-image', methods=['POST'])
@login_required
def upload_activity_image():
    try:
        if 'activity_image' not in request.files:
            return jsonify({'success': False, 'message': 'No file provided'})

        file = request.files['activity_image']
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'})

        if file and allowed_file(file.filename):
            # Process image
            image = Image.open(file)

            # Resize image maintaining aspect ratio
            max_size = (800, 800)
            image.thumbnail(max_size, Image.Resampling.LANCZOS)

            # Convert to RGB if necessary
            if image.mode != 'RGB':
                image = image.convert('RGB')

            # Generate unique filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"activity_{current_user.id}_{timestamp}_{secure_filename(file.filename)}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            # Save processed image
            image.save(filepath, format='JPEG', quality=85)

            # Update user's activity images
            image_url = url_for('static', filename=f'uploads/{filename}')
            if not current_user.activity_images:
                current_user.activity_images = []
            current_user.activity_images.append(image_url)
            db.session.commit()

            return jsonify({
                'success': True,
                'message': 'Image uploaded successfully',
                'image_url': image_url
            })

    except Exception as e:
        app.logger.error(f"Image upload error: {str(e)}")
        return jsonify({'success': False, 'message': 'Error uploading image'})

    return jsonify({'success': False, 'message': 'Invalid file type'})

# Add new route for chat media uploads after the existing upload routes
@app.route('/upload-chat-media', methods=['POST'])
@login_required
def upload_chat_media():
    try:
        if 'media' not in request.files:
            return jsonify({'success': False, 'message': 'No file provided'})

        file = request.files['media']
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'})

        # Define allowed extensions for different media types
        ALLOWED_EXTENSIONS = {
            'image': {'png', 'jpg', 'jpeg', 'gif'},
            'video': {'mp4', 'webm'},
            'audio': {'mp3', 'wav', 'ogg'},
            'document': {'pdf', 'doc', 'docx', 'txt'}
        }

        file_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        media_type = None
        for type_name, extensions in ALLOWED_EXTENSIONS.items():
            if file_ext in extensions:
                media_type = type_name
                break

        if not media_type:
            return jsonify({'success': False, 'message': 'File type not allowed'})

        # Generate unique filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"chat_media_{current_user.id}_{timestamp}_{secure_filename(file.filename)}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        # Process different media types
        if media_type == 'image':
            image = Image.open(file)
            # Resize image maintaining aspect ratio
            image.thumbnail((800, 800), Image.Resampling.LANCZOS)
            image.save(filepath, quality=85, optimize=True)
        else:
            # For other media types, save directly with size limit
            file.save(filepath)

        media_url = url_for('static', filename=f'uploads/{filename}')
        return jsonify({
            'success': True,
            'media_url': media_url,
            'media_type': media_type
        })

    except Exception as e:
        app.logger.error(f"Media upload error: {str(e)}")
        return jsonify({'success': False, 'message': 'Error uploading media'})

# New Routes for Chat

@app.route('/chat/<int:user_id>')
@login_required
def chat(user_id):
    other_user = User.query.get_or_404(user_id)
    messages = DbMessage.query.filter(
        ((DbMessage.sender_id == current_user.id) & (DbMessage.recipient_id == user_id)) |
        ((DbMessage.sender_id == user_id) & (DbMessage.recipient_id == current_user.id))
    ).order_by(DbMessage.created_at.asc()).all()

    # Mark messages as read
    unread_messages = DbMessage.query.filter_by(
        recipient_id=current_user.id,
        sender_id=user_id,
        is_read=False
    ).all()

    for message in unread_messages:
        message.is_read = True
    db.session.commit()

    return render_template('chat.html', other_user=other_user, messages=messages)

@app.route('/messages')
@login_required
def messages():
    # Get list of users current user has chatted with using subqueries
    sent_messages = DbMessage.query.filter_by(sender_id=current_user.id).with_entities(DbMessage.recipient_id).distinct()
    received_messages = DbMessage.query.filter_by(recipient_id=current_user.id).with_entities(DbMessage.sender_id).distinct()

    # Combine both subqueries to get all unique user IDs
    user_ids = [id[0] for id in sent_messages.union(received_messages).all()]

    # Get user objects for these IDs
    chat_partners = User.query.filter(User.id.in_(user_ids)).all()

    # Get all friends using the relationship
    friends = current_user.friends.all()

    return render_template('messages.html', chat_partners=chat_partners, friends=friends)

@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        room = f'user_{current_user.id}'
        join_room(room)
        current_user.last_active = datetime.now(timezone.utc)
        db.session.commit()
        logger.info(f"User {current_user.id} connected and joined room {room}")

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        room = f'user_{current_user.id}'
        leave_room(room)
        logger.info(f"User {current_user.id} disconnected from room {room}")

@socketio.on('send_message')
def handle_message(data):
    if not current_user.is_authenticated:
        return

    recipient_id = data.get('recipient_id')
    content = data.get('content')
    media_url = data.get('media_url')
    media_type = data.get('media_type')

    message = DbMessage(
        sender_id=current_user.id,
        recipient_id=recipient_id,
        content=content,
        media_url=media_url,
        media_type=media_type
    )
    db.session.add(message)

    # Create notification for recipient
    notification = Notification(
        user_id=recipient_id,
        type='message',
        content=f'New message from {current_user.username}',
        related_id=message.id
    )
    db.session.add(notification)
    db.session.commit()

    # Emit the message to both sender and recipient
    message_data = {
        'id': message.id,
        'sender_id': message.sender_id,
        'content': message.content,
        'media_url': message.media_url,
        'media_type': message.media_type,
        'created_at': message.created_at.isoformat(),
        'sender_username': current_user.username
    }

    emit('new_message', message_data, room=f'user_{recipient_id}')
    emit('new_message', message_data, room=f'user_{current_user.id}')

@app.route('/test-message/<int:recipient_id>')
@login_required
def test_message(recipient_id):
    # Create a test message
    message = DbMessage(
        sender_id=current_user.id,
        recipient_id=recipient_id,
        content="Test message"
    )
    db.session.add(message)
    db.session.commit()

    flash('Test message sent successfully!', 'success')
    return redirect(url_for('messages'))

# Add these new routes after the existing chat routes

@app.route('/groups')
@login_required
def groups():
    return render_template('group_chat.html', active_group=None)

@app.route('/group/<int:group_id>')
@login_required
def group_chat(group_id):
    group = ChatGroup.query.get_or_404(group_id)
    messages = GroupMessage.query.filter_by(group_id=group_id).order_by(GroupMessage.created_at.asc()).all()
    return render_template('group_chat.html', active_group=group, messages=messages)

@app.route('/create-group', methods=['POST'])
@login_required
def create_group():
    name = request.form.get('name')
    member_ids = request.form.getlist('members[]')

    if not name:
        flash('Group name is required', 'error')
        return redirect(url_for('groups'))

    try:
        # Create new group
        group = ChatGroup(name=name, created_by=current_user.id)
        db.session.add(group)

        # Add creator as member
        group.members.append(current_user)

        # Add selected members
        for member_id in member_ids:
            member = User.query.get(int(member_id))
            if member and member != current_user:
                group.members.append(member)

        db.session.commit()
        flash('Group created successfully!', 'success')
        return redirect(url_for('group_chat', group_id=group.id))
    except Exception as e:
        app.logger.error(f"Group creation error: {str(e)}")
        flash('Error creating group', 'error')
        db.session.rollback()
        return redirect(url_for('groups'))

# Add these new socket event handlers after the existing ones

@socketio.on('join_group')
def handle_join_group(data):
    if not current_user.is_authenticated:
        return

    group_id = data.get('group_id')
    if group_id:
        join_room(f'group_{group_id}')
        current_user.last_active = datetime.now(timezone.utc)
        db.session.commit()

@socketio.on('group_message')
def handle_group_message(data):
    if not current_user.is_authenticated:
        return

    group_id = data.get('group_id')
    content = data.get('content')
    media_url = data.get('media_url')
    media_type = data.get('media_type')

    group = ChatGroup.query.get(group_id)
    if not group or current_user not in group.members:
        return

    message = GroupMessage(
        group_id=group_id,
        sender_id=current_user.id,
        content=content,
        media_url=media_url,
        media_type=media_type
    )
    db.session.add(message)

    # Create notifications for group members
    for member in group.members:
        if member.id != current_user.id:
            notification = Notification(
                user_id=member.id,
                type='group_message',
                content=f'New message in {group.name} from {current_user.username}',
                related_id=message.id
            )
            db.session.add(notification)

    db.session.commit()

    # Emit the message to all group members
    message_data = {
        'id': message.id,
        'sender_id': message.sender_id,
        'sender_username': current_user.username,
        'content': message.content,
        'media_url': message.media_url,
        'media_type': message.media_type,
        'created_at': message.created_at.isoformat()
    }

    emit('group_message', message_data, room=f'group_{group_id}')


@app.route('/map')
@login_required
def friend_map():
    return render_template('map.html')

@app.route('/api/friend-locations')
@login_required
def friend_locations():
    friends = current_user.friends.all()
    friend_data = []

    for friend in friends:
        if friend.latitude and friend.longitude:
            friend_data.append({
                'id': friend.id,
                'username': friend.username,
                'latitude': friend.latitude,
                'longitude': friend.longitude,
                'profile_picture': friend.profile_picture,
                'last_active': friend.last_active.isoformat() if friend.last_active else None
            })

    return jsonify(friend_data)

@app.route('/api/update-location', methods=['POST'])
@login_required
def update_location():
    data = request.get_json()

    try:
        current_user.latitude = float(data.get('latitude'))
        current_user.longitude = float(data.get('longitude'))
        current_user.last_active = datetime.now(timezone.utc)
        db.session.commit()

        # Notify friends about location update
        friend_ids = [friend.id for friend in current_user.friends]
        location_data = {
            'id': current_user.id,
            'username': current_user.username,
            'latitude': current_user.latitude,
            'longitude': current_user.longitude,
            'profile_picture': current_user.profile_picture,
            'last_active': current_user.last_active.isoformat()
        }

        for friend_id in friend_ids:
            socketio.emit('friend_location_update', location_data, room=f'user_{friend_id}')

        return jsonify({'success': True})
    except Exception as e:
        app.logger.error(f"Location update error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/notifications')
@login_required
def notifications():
    logger.info(f"Fetching notifications for user {current_user.id}")
    try:
        # Get unread notifications
        notifications = Notification.query.filter_by(
            user_id=current_user.id,
            is_read=False
        ).order_by(Notification.created_at.desc()).all()

        logger.debug(f"Found {len(notifications)} unread notifications")
        for notif in notifications:
            logger.debug(f"Notification {notif.id}: {notif.type} - {notif.content}")

        return render_template('notifications.html', notifications=notifications)
    except Exception as e:
        logger.error(f"Error fetching notifications: {str(e)}")
        flash('An error occurred while fetching notifications.', 'danger')
        return render_template('notifications.html', notifications=[])

@app.route('/mark-notification-read/<int:notification_id>')
@login_required
def mark_notification_read(notification_id):
    notification = Notification.query.get_or_404(notification_id)

    if notification.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    notification.is_read = True
    db.session.commit()

    return jsonify({'success': True})

# Add these WebSocket event handlers after the existing ones
@socketio.on('mark_notifications_read')
def handle_mark_notifications_read(data):
    if not current_user.is_authenticated:
        return

    notification_ids = data.get('notification_ids', [])
    if notification_ids:
        Notification.query.filter(
            Notification.id.in_(notification_ids),
            Notification.user_id == current_user.id
        ).update({Notification.is_read: True}, synchronize_session=False)
        db.session.commit()

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)