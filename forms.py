from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField, URLField, SelectField, IntegerField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError, URL, Optional, NumberRange
from models import User

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=64)
    ])
    email = StringField('Email', validators=[
        DataRequired(),
        Email(),
        Length(max=120)
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters long')
    ])
    password2 = PasswordField('Repeat Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already taken.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered.')

class OTPForm(FlaskForm):
    otp_code = StringField('Enter OTP Code', validators=[
        DataRequired(),
        Length(min=6, max=6, message='OTP must be 6 digits')
    ])
    submit = SubmitField('Verify OTP')

class RequestPasswordResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters long')
    ])
    password2 = PasswordField('Repeat Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Reset Password')

class ProfileForm(FlaskForm):
    profile_picture = URLField('Profile Picture URL', validators=[Optional(), URL()])
    bio = TextAreaField('About Me', validators=[Optional(), Length(max=1000)])
    interests = TextAreaField('Interests and Hobbies', validators=[Optional(), Length(max=500)])
    location = StringField('Location', validators=[Optional(), Length(max=120)])

    # Friend finder specific fields
    age = IntegerField('Age', validators=[Optional(), NumberRange(min=18, max=120)])
    looking_for = SelectField('Looking For', choices=[
        ('friendship', 'Friendship'),
        ('activity_partner', 'Activity Partner'),
        ('study_buddy', 'Study Buddy'),
        ('networking', 'Professional Networking')
    ], validators=[Optional()])
    activities = TextAreaField('Favorite Activities', validators=[Optional(), Length(max=500)])
    availability = SelectField('Usually Available', choices=[
        ('weekdays', 'Weekdays'),
        ('weekends', 'Weekends'),
        ('evenings', 'Evenings'),
        ('flexible', 'Flexible')
    ], validators=[Optional()])

    # Privacy settings
    location_visible = BooleanField('Show Location Publicly')
    interests_visible = BooleanField('Show Interests Publicly')
    bio_visible = BooleanField('Show Bio Publicly')
    age_visible = BooleanField('Show Age Publicly')
    activities_visible = BooleanField('Show Activities Publicly')
    availability_visible = BooleanField('Show Availability Publicly')

    submit = SubmitField('Update Profile')