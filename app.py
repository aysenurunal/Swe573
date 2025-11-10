from flask import Flask, render_template, request, redirect, session, url_for, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from config import SQLALCHEMY_DATABASE_URI, SECRET_KEY
import ssl
ssl._create_default_https_context = ssl._create_unverified_context



import os
from uuid import uuid4
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
app.config["SECRET_KEY"] = SECRET_KEY
app.secret_key = SECRET_KEY

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "../uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS= {"png", "jpg", "jpeg","gif"}
app.config["UPLOAD_FOLDER"]= UPLOAD_FOLDER

def allowed_file(name: str) -> bool:
    return "." in name and name.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# ---------- DATABASE MODEL ----------

class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    timebank_balance = db.Column(db.Integer, default=3)
    offers = db.relationship("Offer", backref="user", lazy=True)
    favorites = db.relationship("Favorite", backref="user", lazy=True)


class Offer(db.Model):
    offer_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.user_id"), nullable=False)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False)
    hours = db.Column(db.Integer, nullable=False)
    location = db.Column(db.String(120), nullable=True)
    is_online = db.Column(db.Boolean, default=False)
    image_filename = db.Column(db.String(255), nullable=True)
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)


class Favorite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.user_id"), nullable=False)
    offer_id = db.Column(db.Integer, db.ForeignKey("offer.offer_id"), nullable=False)

# ---------- ROUTES ----------

@app.route("/")
def index():
    offers = Offer.query.all()

    user_favorites = set()
    if "user_id" in session:
        favs = Favorite.query.filter_by(user_id=session["user_id"]).all()
        user_favorites = {f.offer_id for f in favs}

    return render_template("main.html", offers=offers, user_favorites=user_favorites)



@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password_hash, password):
            session["user_id"] = user.user_id
            return redirect(url_for("index"))

        return render_template("login.html", error="Incorrect email or password.")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if password != confirm_password:
            return "Passwords do not match!"

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return "Email is already registered."

        password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
        user = User(email=email, password_hash=password_hash)

        user.timebank_balance = 3

        db.session.add(user)
        db.session.commit()

        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/add-offer", methods=["GET", "POST"])
def add_offer():
    # User must be logged in
    if "user_id" not in session:
        return redirect("/login")

    if request.method == "POST":
        title = request.form["title"]
        description = request.form["description"]
        hours = int(request.form["hours"])
        location = request.form["location"]
        from geopy.geocoders import Nominatim
        from geopy.exc import GeocoderTimedOut
        import time

        geolocator = Nominatim(
            user_agent="the-hive",
            timeout=10,
            scheme="https"
        )

        def safe_geocode(address, attempts=3):
            for i in range(attempts):
                try:
                    return geolocator.geocode(address)
                except GeocoderTimedOut:
                    print(f"Geocode timeout. Retry {i + 1}/{attempts}...")
                    time.sleep(1)
            return None

        location_data = safe_geocode(location)
        lat = location_data.latitude if location_data else None
        lon = location_data.longitude if location_data else None

        #default: no image
        image_filename = None

        # IMAGE UPLOAD HANDLING
        file = request.files.get("image")
        if file and file.filename:
            if allowed_file(file.filename):
                safe_name = secure_filename(file.filename)
                name_prefix=f"user{session['user_id']}_"
                safe_name=name_prefix + safe_name
                save_path = os.path.join(app.config["UPLOAD_FOLDER"],safe_name)
                file.save(save_path)
                image_filename=safe_name
            else:
                return "Unsupported file type. Allowed: png, jpg, jpeg, gif", 400

        offer = Offer(
            user_id=session["user_id"],
            title=title,
            description=description,
            hours=hours,
            location=location,
            is_online=("online" in location.lower()),
            image_filename = image_filename,  #  Save image filename to DB
            latitude = lat,
            longitude = lon
        )

        db.session.add(offer)
        db.session.commit()

        return redirect(url_for("index"))

    return render_template("add_offer.html")

@app.route("/profile")
def profile():
    if "user_id" not in session:
        return redirect("/login")

    user = User.query.get(session["user_id"])
    return render_template("profile.html", user=user)

@app.route("/toggle-favorite/<int:offer_id>", methods=["POST"])
def toggle_favorite(offer_id):
    if "user_id" not in session:
        return redirect("/login")

    fav = Favorite.query.filter_by(user_id=session["user_id"], offer_id=offer_id).first()

    if fav:
        db.session.delete(fav)
    else:
        db.session.add(Favorite(user_id=session["user_id"], offer_id=offer_id))

    db.session.commit()
    return redirect("/")

@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

@app.route("/offer/<int:offer_id>")
def offer_detail(offer_id):
    offer = Offer.query.get_or_404(offer_id)
    return render_template("offer_detail.html", offer=offer)


if __name__ == "__main__":
    app.run(debug=True)
