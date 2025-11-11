

from flask import Flask, render_template, request, redirect, session, url_for, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from config import SQLALCHEMY_DATABASE_URI, SECRET_KEY
import ssl
from datetime import datetime, timedelta

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

# Resimler buraya kaydedilecek:
app.config["UPLOAD_FOLDER"] = os.path.join("static", "uploads")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

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

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.user_id"), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey("user.user_id"), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Proposal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    offer_id = db.Column(db.Integer, db.ForeignKey("offer.offer_id"), nullable=False)
    proposer_id = db.Column(db.Integer, db.ForeignKey("user.user_id"), nullable=False)
    hours = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default="pending")

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
    if "user_id" not in session:
        return redirect("/login")

    if request.method == "POST":
        title = request.form["title"]
        description = request.form["description"]
        hours = int(request.form["hours"])
        location = request.form["location"]

        # --- GEOCODING (Konum → Koordinat) ---
        from geopy.geocoders import Nominatim
        from geopy.exc import GeocoderTimedOut
        import time

        geolocator = Nominatim(user_agent="the-hive", timeout=10)

        def safe_geocode(address, attempts=3):
            for i in range(attempts):
                try:
                    return geolocator.geocode(address)
                except GeocoderTimedOut:
                    time.sleep(1)
            return None

        loc = safe_geocode(location)
        lat = loc.latitude if loc else None
        lon = loc.longitude if loc else None

        # --- IMAGE UPLOAD ---
        image_filename = None
        file = request.files.get("image")

        if file and file.filename:
            if allowed_file(file.filename):
                safe_name = secure_filename(file.filename)
                safe_name = f"user{session['user_id']}_{safe_name}"
                save_path = os.path.join(app.config["UPLOAD_FOLDER"], safe_name)
                file.save(save_path)
                image_filename = safe_name
            else:
                return "Unsupported file type. Allowed: png, jpg, jpeg, gif", 400

        # --- CREATE OFFER ---
        offer = Offer(
            user_id=session["user_id"],
            title=title,
            description=description,
            hours=hours,
            location=location,
            is_online=("online" in location.lower()),
            image_filename=image_filename,
            latitude=lat,
            longitude=lon
        )

        db.session.add(offer)
        db.session.commit()

        return redirect(url_for("index"))

    return render_template("add_offer.html")


@app.route("/profile")
def my_profile():
    if "user_id" not in session:
        return redirect("/login")

    user = User.query.get(session["user_id"])
    return render_template("profile.html", user=user)

@app.route("/user/<int:user_id>")
def profile(user_id):
    user = User.query.get_or_404(user_id)
    user_offers = Offer.query.filter_by(user_id=user_id).all()
    return render_template("profile.html", user=user, offers=user_offers)

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


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/message/<int:to_user_id>", methods=["GET", "POST"])
def send_message(to_user_id):
    if "user_id" not in session:
        return redirect("/login")

    my_id = session["user_id"]
    receiver = User.query.get_or_404(to_user_id)

    # Eğer POST ise mesaj gönder
    if request.method == "POST":
        content = request.form.get("content", "").strip()
        if content:   # ✅ BOŞ MESAJ EKLENMESİN
            new_msg = Message(
                sender_id=my_id,
                receiver_id=to_user_id,
                content=content   # ✅ BURASI DÜZELDİ
            )
            db.session.add(new_msg)
            db.session.commit()

        return redirect(url_for("send_message", to_user_id=to_user_id))

    # Sohbet geçmişi (iki yönlü)
    chat_messages = Message.query.filter(
        ((Message.sender_id == my_id) & (Message.receiver_id == to_user_id)) |
        ((Message.sender_id == to_user_id) & (Message.receiver_id == my_id))
    ).order_by(Message.timestamp.asc()).all()

    return render_template("messages.html", messages=chat_messages, other=receiver)

@app.route("/chat/<int:user_id>", methods=["GET", "POST"])
def chat(user_id):
    if "user_id" not in session:
        return redirect("/login")

    user1 = session["user_id"]   # Sen
    user2 = user_id              # Görüştüğün kişi

    other_user = User.query.get_or_404(user2)

    # Mesaj gönderme
    if request.method == "POST":
        text = request.form["message"].strip()
        if text:
            msg = Message(sender_id=user1, receiver_id=user2, content=text)
            db.session.add(msg)
            db.session.commit()
        return redirect(url_for("chat", user_id=user2))

    # Sohbet geçmişini çek
    messages = Message.query.filter(
        ((Message.sender_id == user1) & (Message.receiver_id == user2)) |
        ((Message.sender_id == user2) & (Message.receiver_id == user1))
    ).order_by(Message.timestamp.asc()).all()

    return render_template("chat.html", other_user=other_user, messages=messages)



@app.route("/chat/<int:offer_id>", methods=["GET", "POST"])
def start_chat(offer_id):
    if "user_id" not in session:
        return redirect("/login")

    offer = Offer.query.get_or_404(offer_id)
    sender_id = session["user_id"]
    receiver_id = offer.user_id

    # GET → Mesajları göster
    if request.method == "GET":
        messages = Message.query.filter(
            ((Message.sender_id==sender_id) & (Message.receiver_id==receiver_id)) |
            ((Message.sender_id==receiver_id) & (Message.receiver_id==sender_id))
        ).order_by(Message.timestamp).all()

        return render_template("chat.html", messages=messages, receiver=offer.user)

    # POST → Mesaj gönder
    if request.method == "POST":
        text = request.form["text"]
        msg = Message(sender_id=sender_id, receiver_id=receiver_id, text=text)
        db.session.add(msg)
        db.session.commit()
        return redirect(url_for("start_chat", offer_id=offer_id))

@app.route("/messages")
def messages_list():
    if "user_id" not in session:
        return redirect("/login")

    my_id = session["user_id"]

    # Konuştuğum herkesin listesi:
    conversations = (
        db.session.query(
            User.user_id,
            User.email,
            db.func.max(Message.timestamp).label("last_time"),
            db.func.max(Message.content).label("last_message")
        )
        .join(Message, ((Message.sender_id == User.user_id) | (Message.receiver_id == User.user_id)))
        .filter((Message.sender_id == my_id) | (Message.receiver_id == my_id))
        .filter(User.user_id != my_id)
        .group_by(User.user_id, User.email)
        .order_by(db.desc("last_time"))
        .all()
    )

    return render_template("messages_list.html", conversations=conversations)


@app.route("/proposal/<int:offer_id>", methods=["POST"])
def make_proposal(offer_id):
    if "user_id" not in session:
        return redirect("/login")

    hours = int(request.form["hours"])
    proposal = Proposal(offer_id=offer_id, proposer_id=session["user_id"], hours=hours)
    db.session.add(proposal)
    db.session.commit()
    return redirect(url_for("offer_detail", offer_id=offer_id))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000,debug=True)

