"""Application configuration values."""

import os

# Allow the database connection to be configured via environment variables.
# When no explicit DATABASE_URL is provided we fall back to using a host name
# that works for local development instead of the Docker specific "db" value
# which causes "could not translate host name" errors outside the container.
DEFAULT_DB_HOST = os.getenv("DATABASE_HOST", "localhost")
DEFAULT_DB_URL = os.getenv(
    "DATABASE_URL",
    f"postgresql://postgres:postgres@{DEFAULT_DB_HOST}:5432/thehive",
)

SQLALCHEMY_DATABASE_URI = DEFAULT_DB_URL
SQLALCHEMY_TRACK_MODIFICATIONS = False
SECRET_KEY = "super-secret-key"
