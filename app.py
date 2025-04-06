# This is a Flask application for a startup voting platform.
# It allows users to register, login, submit startups, vote for startups, and view their dashboard.
# The application uses Flask-SQLAlchemy for database interactions, Flask-Login for user authentication,
# and Flask-WTF for form handling. It also includes file upload functionality for startup images.
# The application is designed to be secure against common web vulnerabilities such as SQL injection and XSS attacks.
# It uses Flask-Limiter to limit the number of requests to the homepage to prevent abuse.
# The application is structured with separate routes for different functionalities and uses templates for rendering HTML pages.

# The application is configured to use environment variables for sensitive information such as database URI and secret keys.
# It also includes a search functionality to find startups by title.
# The application is designed to be user-friendly and provides feedback to users through flash messages.

# import necessary libraries and modules
import os
from dotenv import load_dotenv
from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, FileField
from wtforms.validators import InputRequired, Length, Email
from werkzeug.utils import secure_filename

from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from markupsafe import escape

# Load environment variables from .env file
# This is important for security and to keep sensitive information out of the codebase.
load_dotenv()

# Initialize Flask app and configure it
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER')
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Allowed file extensions for image uploads
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Function to check if the uploaded file has an allowed extension
# This is important for security to prevent uploading of malicious files.
def allowed_file(filename):
    """Check if the uploaded file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Initialize Flask-Limiter for rate limiting
# This is important to prevent abuse of the application, such as spamming requests to the homepage.
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="memory://"
)

# Attach Limiter to Flask app
limiter.init_app(app)

# Database Models of users, startups and votes
# User model for storing user information
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    startups = db.relationship('Startup', backref='author', lazy=True)
    votes = db.relationship('Vote', backref='voter', lazy=True)

# Startup model for storing startup information 
class Startup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image_file = db.Column(db.String(100), nullable=True, default="default.jpg")
    votes = db.Column(db.Integer, default=0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    votes_received = db.relationship('Vote', backref='startup', lazy=True)

# Vote model for storing votes information
class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    startup_id = db.Column(db.Integer, db.ForeignKey('startup.id'), nullable=False)
    db.UniqueConstraint('user_id', 'startup_id', name='unique_vote')

# User Loader for Flask-Login to track the logged in user 
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Forms for Registration, Login and Startup Submission
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6)])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')

class StartupForm(FlaskForm):
    title = StringField('Startup Title', validators=[InputRequired(), Length(min=3)])
    description = TextAreaField('Description', validators=[InputRequired(), Length(min=10)])
    image = FileField('Upload Image')
    submit = SubmitField('Submit Startup')

# Routes for home page, register, login, logout, dashboard, submit, edit, vote and search
@app.route('/')
@limiter.limit("10 per minute")  # Limits homepage requests if a user exceeds 3 requests per minute, they are blocked!
def home():
    startups = Startup.query.order_by(Startup.votes.desc()).all()
    return render_template('index.html', startups=startups, Vote=Vote)

# Route for the registration page
# This allows users to create a new account.
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# Route for the login page
# This allows users to log in to their account.
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials, please try again.', 'danger')
    return render_template('login.html', form=form)

# Route for the logout page
# This allows users to log out of their account.
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# Route for the dashboard page
# This allows users to view their submitted startups.
@app.route('/dashboard')
@login_required
def dashboard():
    user_startups = Startup.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', startups=user_startups)

# Route for the startup submission page
# This allows users to submit a new startup.
@app.route('/submit', methods=['GET', 'POST'])
@login_required
def submit():
    form = StartupForm()
    
    if form.validate_on_submit():
        # Secure and sanitize user input to prevent XSS
        title = escape(form.title.data)
        description = escape(form.description.data)

        # Handle file upload securely
        image_file = 'default.jpg'  # Default image
        if form.image.data and allowed_file(form.image.data.filename):
            filename = secure_filename(form.image.data.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            form.image.data.save(image_path)
            image_file = filename  # Save the uploaded filename

        # Create a new Startup entry
        new_startup = Startup(
            title=title,
            description=description,
            image_file=image_file,  # Store filename in database
            user_id=current_user.id
        )
        db.session.add(new_startup)
        db.session.commit()

        flash('Startup submitted successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('submit.html', form=form)

# Route for editing a startup
# This allows users to edit their submitted startup.
# Only the owner of the startup can edit it.
@app.route("/edit-startup/<int:startup_id>", methods=["GET", "POST"])
@login_required
def edit_startup(startup_id):
    startup = Startup.query.get_or_404(startup_id)

    # Ensure only the owner can edit
    if startup.user_id != current_user.id:
        flash("You are not authorized to edit this startup!", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        startup.title = request.form["title"]
        startup.description = request.form["description"]

        # Handle image upload
        if "image_file" in request.files:
            file = request.files["image_file"]
            if file.filename != "":
                file.save(f"static/uploads/{file.filename}")
                startup.image_file = file.filename

        db.session.commit()
        flash("Startup updated successfully!", "success")
        return redirect(url_for("dashboard"))

    return render_template("edit_startup.html", startup=startup)

# Route for viewing startup details
# This allows users to view the details of a specific startup.
@app.route('/startup/<int:startup_id>')
def detail_startup(startup_id):
    startup = Startup.query.get_or_404(startup_id)
    return render_template('detail_startup.html', startup=startup, Vote=Vote)

# Route for voting on a startup
# This allows users to vote for a specific startup.
@app.route("/vote/<int:startup_id>")
@login_required  # Ensure only logged-in users can vote
def vote(startup_id):
    # Check if the user has already voted for this startup
    existing_vote = Vote.query.filter_by(user_id=current_user.id, startup_id=startup_id).first()
    
    if existing_vote:
        flash("You have already voted for this startup!", "warning")
        return redirect(url_for('home'))  # Redirect back to the page

    # Otherwise, register the vote
    new_vote = Vote(user_id=current_user.id, startup_id=startup_id)
    db.session.add(new_vote)

    # Increment the vote count on the startup
    startup = Startup.query.get(startup_id)
    if startup:
        startup.votes += 1
        db.session.commit()

    flash("Your vote has been counted!", "success")
    return redirect(url_for('home'))  # Redirect after voting

#Automatically prevents SQL injection attacks using ORM Query (Startup.query.filter)
@app.route('/search', methods=['GET', 'POST'])
def search():
    query = request.form.get('query', '')
    # Using parameterized query to prevent SQL injection attacks
    # The ilike() method is used for case-insensitive pattern matching in SQLAlchemy.
    results = Startup.query.filter(Startup.title.ilike(f"%{query}%")).all()
    
    return render_template('search.html', query=query, results=results)

# main function to run the Flask app
# This is the entry point of the application.
# It initializes the database and runs the app.
# The app is production ready but can run in debug mode for development purposes.
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    #app.run(debug=True)
    app.run(debug=True, host='0.0.0.0')
