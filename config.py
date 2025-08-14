import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "your_secret_key")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your_jwt_secret")
    GOOGLE_OAUTH_CLIENT_ID = os.getenv("GOOGLE_OAUTH_CLIENT_ID")
    GOOGLE_OAUTH_CLIENT_SECRET = os.getenv("GOOGLE_OAUTH_CLIENT_SECRET")
    FACEBOOK_OAUTH_CLIENT_ID = os.getenv("FACEBOOK_OAUTH_CLIENT_ID")
    FACEBOOK_OAUTH_CLIENT_SECRET = os.getenv("FACEBOOK_OAUTH_CLIENT_SECRET")
    LINKEDIN_OAUTH_CLIENT_ID = os.getenv("LINKEDIN_OAUTH_CLIENT_ID")
    LINKEDIN_OAUTH_CLIENT_SECRET = os.getenv("LINKEDIN_OAUTH_CLIENT_SECRET")
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")