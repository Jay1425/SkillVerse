from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash

# ----------------------------
# Flask App & Config
# ----------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///skillverse.db'

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
    form = SignupForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash("Email already registered.")
            return redirect(url_for('signup'))
        user = User(
            username=form.username.data,
            email=form.email.data,
            password=generate_password_hash(form.password.data),
            auth_type='email'
        )
        db.session.add(user)
        db.session.commit()
        flash("Signup successful! Please log in.")
        return redirect(url_for('login'))
    return render_template('signUp.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data, auth_type='email').first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash("Invalid login credentials.")
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

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
# Create DB Tables on First Run
# ----------------------------
with app.app_context():
    db.create_all()

# ----------------------------
# Run Server
# ----------------------------
if __name__ == '__main__':
    app.run(debug=True)
