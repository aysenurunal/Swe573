import os

SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@db:5432/thehive")
SQLALCHEMY_TRACK_MODIFICATIONS = False
SECRET_KEY = "super-secret-key"
