import os

# Ortamı belirle (default: development)
ENV = os.getenv("FLASK_ENV", "development")

# DATABASE ----------------------------------------------------

if ENV == "development":
    # LOCAL ortamda SQLite kullan
    SQLALCHEMY_DATABASE_URI = "sqlite:///local.db"
else:
    # PRODUCTION (DigitalOcean) PostgreSQL kullanır
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        "postgresql://postgres:postgres@db:5432/thehive"
    )

SQLALCHEMY_TRACK_MODIFICATIONS = False

# SECRET KEY --------------------------------------------------
SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-key")

# ADMIN USER --------------------------------------------------
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@thehive.local")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "change-me-now")