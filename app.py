from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField
from wtforms.validators import InputRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

# ----------------------------
# Flask App & Config
# ----------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_secret_key_here_change_in_production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///skillverse.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ----------------------------
# Extensions
# ----------------------------
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ----------------------------
# Models
# ----------------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=True)  # Optional for Google accounts
    auth_type = db.Column(db.String(50), nullable=False, default='email')  # 'email' or 'google'
    bio = db.Column(db.Text, nullable=True)
    location = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    skills_offering = db.relationship('Skill', backref='user', lazy=True, foreign_keys='Skill.user_id')
    swap_requests = db.relationship('SwapRequest', backref='requester', lazy=True, foreign_keys='SwapRequest.requester_id')
    swap_offers = db.relationship('SwapRequest', backref='offerer', lazy=True, foreign_keys='SwapRequest.offerer_id')

class Skill(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    level = db.Column(db.String(20), nullable=False)  # Beginner, Intermediate, Advanced
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

class SwapRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    skill_wanted = db.Column(db.String(100), nullable=False)
    skill_offered = db.Column(db.String(100), nullable=False)
    requester_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    offerer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    status = db.Column(db.String(20), default='open')  # open, accepted, completed, cancelled
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)

# ----------------------------
# Forms
# ----------------------------
class SignupForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=3, max=150)])
    email = StringField("Email", validators=[InputRequired(), Email()])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=6)])
    submit = SubmitField("Create Account")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Email()])
    password = PasswordField("Password", validators=[InputRequired()])
    submit = SubmitField("Login")

class SkillForm(FlaskForm):
    name = StringField("Skill Name", validators=[InputRequired(), Length(max=100)])
    description = TextAreaField("Description", validators=[InputRequired()])
    category = SelectField("Category", choices=[
        ('programming', 'Programming'),
        ('design', 'Design'),
        ('marketing', 'Marketing'),
        ('languages', 'Languages'),
        ('music', 'Music'),
        ('cooking', 'Cooking'),
        ('fitness', 'Fitness'),
        ('other', 'Other')
    ], validators=[InputRequired()])
    level = SelectField("Level", choices=[
        ('beginner', 'Beginner'),
        ('intermediate', 'Intermediate'),
        ('advanced', 'Advanced')
    ], validators=[InputRequired()])
    submit = SubmitField("Add Skill")

class SwapRequestForm(FlaskForm):
    title = StringField("Title", validators=[InputRequired(), Length(max=200)])
    description = TextAreaField("Description", validators=[InputRequired()])
    skill_wanted = StringField("Skill Wanted", validators=[InputRequired(), Length(max=100)])
    skill_offered = StringField("Skill Offered", validators=[InputRequired(), Length(max=100)])
    submit = SubmitField("Create Request")

# ----------------------------
# Login Manager Loader
# ----------------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ----------------------------
# Routes
# ----------------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = SignupForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash("Email already registered.", "error")
            return redirect(url_for('signup'))
        
        user = User(
            username=form.username.data,
            email=form.email.data,
            password=generate_password_hash(form.password.data),
            auth_type='email'
        )
        db.session.add(user)
        db.session.commit()
        flash("Signup successful! Please log in.", "success")
        return redirect(url_for('login'))
    return render_template('signUp.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data, auth_type='email').first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash("Welcome back!", "success")
            return redirect(url_for('dashboard'))
        flash("Invalid login credentials.", "error")
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_skills = Skill.query.filter_by(user_id=current_user.id, is_active=True).all()
    open_requests = SwapRequest.query.filter_by(status='open').order_by(SwapRequest.created_at.desc()).limit(5).all()
    user_requests = SwapRequest.query.filter_by(requester_id=current_user.id).order_by(SwapRequest.created_at.desc()).all()
    
    return render_template('dashboard.html', 
                         user=current_user, 
                         skills=user_skills, 
                         open_requests=open_requests,
                         user_requests=user_requests)

@app.route('/profile')
@login_required
def profile():
    user_skills = Skill.query.filter_by(user_id=current_user.id, is_active=True).all()
    return render_template('profile.html', user=current_user, skills=user_skills)

@app.route('/browse')
def browse():
    skills = Skill.query.filter_by(is_active=True).order_by(Skill.created_at.desc()).all()
    return render_template('browse.html', skills=skills)

@app.route('/add-skill', methods=['GET', 'POST'])
@login_required
def add_skill():
    form = SkillForm()
    if form.validate_on_submit():
        skill = Skill(
            name=form.name.data,
            description=form.description.data,
            category=form.category.data,
            level=form.level.data,
            user_id=current_user.id
        )
        db.session.add(skill)
        db.session.commit()
        flash("Skill added successfully!", "success")
        return redirect(url_for('dashboard'))
    return render_template('add_skill.html', form=form)

@app.route('/create-request', methods=['GET', 'POST'])
@login_required
def create_request():
    form = SwapRequestForm()
    if form.validate_on_submit():
        request_obj = SwapRequest(
            title=form.title.data,
            description=form.description.data,
            skill_wanted=form.skill_wanted.data,
            skill_offered=form.skill_offered.data,
            requester_id=current_user.id
        )
        db.session.add(request_obj)
        db.session.commit()
        flash("Swap request created successfully!", "success")
        return redirect(url_for('dashboard'))
    return render_template('create_request.html', form=form)

@app.route('/requests')
def requests():
    all_requests = SwapRequest.query.filter_by(status='open').order_by(SwapRequest.created_at.desc()).all()
    return render_template('requests.html', requests=all_requests)

@app.route('/my-swaps')
@login_required
def my_swaps():
    user_requests = SwapRequest.query.filter_by(requester_id=current_user.id).order_by(SwapRequest.created_at.desc()).all()
    return render_template('my_swaps.html', requests=user_requests)

@app.route('/accept-request/<int:request_id>', methods=['POST'])
@login_required
def accept_request(request_id):
    swap_request = SwapRequest.query.get_or_404(request_id)
    if swap_request.status != 'open':
        flash("This request is no longer available.", "error")
        return redirect(url_for('requests'))
    
    swap_request.offerer_id = current_user.id
    swap_request.status = 'accepted'
    db.session.commit()
    flash("Request accepted! Contact the requester to arrange the swap.", "success")
    return redirect(url_for('requests'))

@app.route('/complete-swap/<int:request_id>', methods=['POST'])
@login_required
def complete_swap(request_id):
    swap_request = SwapRequest.query.get_or_404(request_id)
    if swap_request.requester_id != current_user.id and swap_request.offerer_id != current_user.id:
        flash("You are not authorized to complete this swap.", "error")
        return redirect(url_for('my_swaps'))
    
    swap_request.status = 'completed'
    swap_request.completed_at = datetime.utcnow()
    db.session.commit()
    flash("Swap completed successfully!", "success")
    return redirect(url_for('my_swaps'))

# ----------------------------
# Google OAuth (Handled by Frontend)
# ----------------------------
@app.route('/google-auth', methods=['POST'])
def google_auth():
    """
    Frontend sends:
    {
      "email": "user@example.com",
      "name": "User Name"
    }
    """
    data = request.get_json()
    email = data.get("email")
    name = data.get("name")

    if not email or not name:
        return jsonify({"error": "Missing email or name"}), 400

    user = User.query.filter_by(email=email).first()

    if not user:
        # Register new Google user
        user = User(
            username=name,
            email=email,
            password=None,
            auth_type='google'
        )
        db.session.add(user)
        db.session.commit()

    login_user(user)
    return jsonify({"message": "Logged in via Google"}), 200

# ----------------------------
# Error Handlers
# ----------------------------
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

# ----------------------------
# Create DB Tables on First Run
# ----------------------------
with app.app_context():
    db.create_all()

# ----------------------------
# Run Server
# ----------------------------
if __name__ == '__main__':
    app.run(debug=True)
