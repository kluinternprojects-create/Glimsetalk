import os
import secrets
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, redirect, url_for, request, jsonify, session
from models import db, User
from config import Config
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook
from flask_dance.contrib.linkedin import make_linkedin_blueprint, linkedin
from flask_session import Session
from openai import OpenAI  # keep if you will call OpenAI
# NOTE: do not create a new SQLAlchemy() here

load_dotenv()
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # local testing only

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "your_secret_key")
app.config["SQLALCHEMY_DATABASE_URI"]= 'sqlite:///Glimsetalk.db'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY", "your_jwt_secret")
app.config.from_object(Config)

# Initialize extensions (bind the db instance from models.py to the app)
db.init_app(app)
jwt = JWTManager(app)

app.config['SESSION_TYPE'] = 'filesystem'  # or 'redis', 'sqlalchemy', etc.
app.config['SECRET_KEY'] = 'your-secret-key'
Session(app)


# OAuth blueprints
google_bp = make_google_blueprint(
    client_id=app.config.get("GOOGLE_OAUTH_CLIENT_ID"),
    client_secret=app.config.get("GOOGLE_OAUTH_CLIENT_SECRET"),
    scope=["profile", "email"],
    redirect_to="google_login"
)
app.register_blueprint(google_bp, url_prefix="/login")

facebook_bp = make_facebook_blueprint(
    client_id=app.config.get("FACEBOOK_OAUTH_CLIENT_ID"),
    client_secret=app.config.get("FACEBOOK_OAUTH_CLIENT_SECRET"),
    scope=["email"],
    redirect_to="facebook_login"
)
app.register_blueprint(facebook_bp, url_prefix="/login")

linkedin_bp = make_linkedin_blueprint(
    client_id=app.config.get("LINKEDIN_OAUTH_CLIENT_ID"),
    client_secret=app.config.get("LINKEDIN_OAUTH_CLIENT_SECRET"),
    scope=["openid", "profile", "email"],
    redirect_to="linkedin_login"
)
app.register_blueprint(linkedin_bp, url_prefix="/login")


@app.route("/")
def index():
    return """
    <h1>Welcome to Glimsetalk!</h1>
    <ul>
        <li><a href="/login/google">Login with Google</a></li>
        <li><a href="/login/facebook">Login with Facebook</a></li>
        <li><a href="/login/linkedin">Login with LinkedIn</a></li>
    </ul>
    """

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password_input = data.get('password')

    if not username or not email or not password_input:
        return jsonify({"message": "All fields are required!"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"message": "Email already registered!"}), 400

    new_user = User(username=username, email=email, password=password_input)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "Registration successful!"})


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password_input = data.get('password')

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password_input):
        return jsonify({"message": "Invalid credentials!"}), 401

    access_token = create_access_token(identity=str(user.id))
    return jsonify({"message": "Login successful!", "token": access_token})


@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify({"message": f"Hello user {current_user}, you are authorized!"})

# ---------------- Social logins ----------------
@app.route("/login/google")
def google_login():
    if not google.authorized:
        return redirect(url_for("google.login"))
    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        return "Failed to fetch Google user info", 400
    user_info = resp.json()
    return handle_social_login(user_info.get("email"), user_info.get("name"))

@app.route("/login/facebook")
def facebook_login():
    if not facebook.authorized:
        return redirect(url_for("facebook.login"))
    resp = facebook.get("/me?fields=id,name,email")
    if not resp.ok:
        return "Failed to fetch Facebook user info", 400
    user_info = resp.json()
    return handle_social_login(user_info.get("email"), user_info.get("name"))

@app.route("/login/linkedin")
def linkedin_login():
    if not linkedin.authorized:
        return redirect(url_for("linkedin.login"))
    email_resp = linkedin.get("emailAddress?q=members&projection=(elements*(handle~))")
    profile_resp = linkedin.get("me?projection=(id,localizedFirstName,localizedLastName)")
    if not email_resp.ok or not profile_resp.ok:
        return "Failed to fetch LinkedIn user info", 400
    email_data = email_resp.json()
    profile_data = profile_resp.json()
    email = email_data["elements"][0]["handle~"]["emailAddress"]
    name = f"{profile_data['localizedFirstName']} {profile_data['localizedLastName']}"
    return handle_social_login(email, name)

def handle_social_login(email, name):
    if not email or not name:
        return jsonify({"error": "Missing user information"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        # social accounts don't provide password — generate a random one and hash it
        random_password = secrets.token_urlsafe(16)
        hashed_password = generate_password_hash(random_password)
        user = User(username=name, email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()

    access_token = create_access_token(identity=email)
    return jsonify({"message": "Login successful", "email": email, "name": name, "access_token": access_token})

# ---------------- Protected chat (requires JWT) ----------------
@app.route("/chat", methods=["POST"])
@jwt_required()
def chat():
    user_email = get_jwt_identity()
    data = request.get_json(force=True)
    user_input = data.get("prompt")
    if not user_input:
        return jsonify({"error": "No prompt provided"}), 400

    # call OpenAI if you have API key configured
    try:
        client = OpenAI(api_key=app.config.get("OPENAI_API_KEY"))
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": user_input}
            ]
        )
        reply = response.choices[0].message.content
        return jsonify({"user": user_email, "response": reply})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
