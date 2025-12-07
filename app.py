

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
@app.before_request
def initialize_database():
    if not getattr(app, "db_initialized", False):
        with app.app_context():
            db.create_all()
        app.db_initialized = True



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
    needs = db.relationship("Need", backref="user", lazy=True)
    favorites = db.relationship("Favorite", backref="user", lazy=True)
    need_favorites = db.relationship("NeedFavorite", backref="user", lazy=True)

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

class Need(db.Model):
    need_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.user_id"), nullable=False)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False)
    hours = db.Column(db.Integer, nullable=False)
    location = db.Column(db.String(120), nullable=True)
    is_online = db.Column(db.Boolean, default=False)
    image_filename = db.Column(db.String(255), nullable=True)
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)

class NeedFavorite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.user_id"), nullable=False)
    need_id = db.Column(db.Integer, db.ForeignKey("need.need_id"), nullable=False)

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
    listing_id= db.Column(db.Integer, nullable=True)  # İlgili ilan ID'si (opsiyonel)
    listing_type = db.Column(db.String(10), nullable=False)  # 'offer' veya 'need' (opsiyonel)
#----------------------DEAL MODEL-----------------------
class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    listing_type = db.Column(db.String(10), nullable=False)   # 'offer' or 'need'
    listing_id = db.Column(db.Integer, nullable=False)

    starter_id = db.Column(db.Integer, db.ForeignKey("user.user_id"), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey("user.user_id"), nullable=False)

    hours = db.Column(db.Integer, nullable=False)
    date = db.Column(db.DateTime, nullable=False)

    starter_confirm = db.Column(db.Boolean, default=False)
    receiver_confirm = db.Column(db.Boolean, default=False)

    cancel_starter_confirm = db.Column(db.Boolean, default=False)
    cancel_receiver_confirm = db.Column(db.Boolean, default=False)

    status = db.Column(db.String(20), default="pending")
    # pending → accepted → completed

# ---------- ROUTES ----------

@app.route("/")
def index():
    offers = Offer.query.all()
    needs = Need.query.all()

    user_favorites = set()
    user_need_favorites = set()
    if "user_id" in session:
        favs = Favorite.query.filter_by(user_id=session["user_id"]).all()
        user_favorites = {f.offer_id for f in favs}

        need_favs = NeedFavorite.query.filter_by(user_id=session["user_id"]).all()
        user_need_favorites = {f.need_id for f in need_favs}

    return render_template(
        "main.html",
        offers=offers,
        needs=needs,
        user_favorites=user_favorites,
        user_need_favorites=user_need_favorites,
    )

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

@app.route("/needs")
def needs_page():
    needs = Need.query.all()

    user_need_favorites = set()
    if "user_id" in session:
        need_favs = NeedFavorite.query.filter_by(user_id=session["user_id"]).all()
        user_need_favorites = {f.need_id for f in need_favs}

    return render_template("needs.html",
                           needs=needs,
                           user_need_favorites=user_need_favorites)

@app.route("/offers")
def offers_page():
    offers = Offer.query.all()

    # Eğer kullanıcı giriş yaptıysa favorilerini çek
    user_favorites = set()
    if "user_id" in session:
        favs = Favorite.query.filter_by(user_id=session["user_id"]).all()
        user_favorites = {f.offer_id for f in favs}

    return render_template("offers.html", offers=offers, user_favorites=user_favorites)

@app.route("/favorites")
def favorites_page():
    if "user_id" not in session:
        return redirect("/login")

    user_id = session["user_id"]

    # ⭐ Favori offers
    fav_offer_ids = {f.offer_id for f in Favorite.query.filter_by(user_id=user_id).all()}
    favorite_offers = Offer.query.filter(Offer.offer_id.in_(fav_offer_ids)).all() if fav_offer_ids else []

    # ⭐ Favori needs
    fav_need_ids = {f.need_id for f in NeedFavorite.query.filter_by(user_id=user_id).all()}
    favorite_needs = Need.query.filter(Need.need_id.in_(fav_need_ids)).all() if fav_need_ids else []

    return render_template(
        "favorites.html",
        favorite_offers=favorite_offers,
        favorite_needs=favorite_needs,
        fav_offer_ids=fav_offer_ids,
        fav_need_ids=fav_need_ids,
    )


@app.route("/add-need", methods=["GET", "POST"])
def add_need():
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

        geolocator = Nominatim(user_agent="the-hive", timeout=10)

        def safe_geocode(address, attempts=3):
            for _ in range(attempts):
                try:
                    return geolocator.geocode(address)
                except GeocoderTimedOut:
                    time.sleep(1)
            return None

        loc = safe_geocode(location)
        lat = loc.latitude if loc else None
        lon = loc.longitude if loc else None

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

        need = Need(
            user_id=session["user_id"],
            title=title,
            description=description,
            hours=hours,
            location=location,
            is_online=("online" in location.lower()),
            image_filename=image_filename,
            latitude=lat,
            longitude=lon,
        )

        db.session.add(need)
        db.session.commit()

        return redirect(url_for("index"))

    return render_template("add_need.html")

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

    # Kullanıcı DB’de yoksa → session’ı temizle ve login’e gönder
    if user is None:
        session.clear()
        return redirect("/login")

    user_offers = Offer.query.filter_by(user_id=user.user_id).all()

    return render_template("profile.html", user=user, offers=user_offers)


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
    return redirect(request.referrer or "/")

@app.route("/toggle-need-favorite/<int:need_id>", methods=["POST"])
def toggle_need_favorite(need_id):
    if "user_id" not in session:
        return redirect("/login")

    fav = NeedFavorite.query.filter_by(user_id=session["user_id"], need_id=need_id).first()

    if fav:
        db.session.delete(fav)
    else:
        db.session.add(NeedFavorite(user_id=session["user_id"], need_id=need_id))

    db.session.commit()
    return redirect(request.referrer or "/")

@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

@app.route("/offer/<int:offer_id>")
def offer_detail(offer_id):
    offer = Offer.query.get_or_404(offer_id)

    user_favorites = set()
    if "user_id" in session:
        favs = Favorite.query.filter_by(user_id=session["user_id"]).all()
        user_favorites = {f.offer_id for f in favs}

    return render_template(
        "offer_detail.html",
        offer=offer,
        user_favorites=user_favorites
    )

@app.route("/need/<int:need_id>")
def need_detail(need_id):
    need = Need.query.get_or_404(need_id)

    user_need_favorites = set()
    if "user_id" in session:
        favs = NeedFavorite.query.filter_by(user_id=session["user_id"]).all()
        user_need_favorites = {f.need_id for f in favs}

    return render_template(
        "need_detail.html",
        need=need,
        user_need_favorites=user_need_favorites
    )

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

# -------------------- CHAT SYSTEM --------------------

@app.route("/chat/<int:user_id>", methods=["GET", "POST"])
def chat(user_id):
    if "user_id" not in session:
        return redirect("/login")

    user1 = session["user_id"]
    user2 = user_id

    # -------------------- LISTING INFO --------------------
    listing_id = request.args.get("listing_id")
    listing_type = request.args.get("type")

    if listing_id:
        session["active_listing_id"] = listing_id
        session["active_listing_type"] = listing_type

    other_user = User.query.get_or_404(user2)

    # -------------------- LISTING SUMMARY --------------------
    listing_data = None

    listing_id = session.get("active_listing_id")
    listing_type = session.get("active_listing_type")

    if listing_id and listing_type:
        if listing_type == "offer":
            listing = Offer.query.get(listing_id)
        else:
            listing = Need.query.get(listing_id)

        if listing:
            listing_data = {
                "type": listing_type,
                "title": listing.title,
                "hours": listing.hours,
                "location": listing.location,
                "id": listing_id
            }

    # -------------------- SEND MESSAGE --------------------
    if request.method == "POST":
        text = request.form["message"].strip()
        if text:
            msg = Message(
                sender_id=user1,
                receiver_id=user2,
                content=text,
                listing_id=session.get("active_listing_id"),
                listing_type=session.get("active_listing_type")
            )

            db.session.add(msg)
            db.session.commit()
        return redirect(url_for("chat", user_id=user2))

    # -------------------- GET ALL MESSAGES --------------------
    messages = Message.query.filter(
        ((Message.sender_id == user1) & (Message.receiver_id == user2)) |
        ((Message.sender_id == user2) & (Message.receiver_id == user1))
        &
        (Message.listing_id == session.get("active_listing_id"))
        &
        (Message.listing_type == session.get("active_listing_type"))
    ).all()

    # -------------------- GET ALL DEALS --------------------
    deals = Transaction.query.filter(
        (
                ((Transaction.starter_id == user1) & (Transaction.receiver_id == user2)) |
                ((Transaction.starter_id == user2) & (Transaction.receiver_id == user1))
        ) &
        (Transaction.listing_id == session.get("active_listing_id"))
    ).all()

    # -------------------- BUILD TIMELINE --------------------
    timeline = []

    for m in messages:
        timeline.append({
            "type": "message",
            "timestamp": m.timestamp,
            "sender_id": m.sender_id,
            "content": m.content
        })

    for d in deals:
        timeline.append({
            "type": "deal",
            "timestamp": d.date,  # deal'ın gerçekleşme zamanı
            "deal": d
        })

    # 🔥 Hepsini zaman sırasına göre sırala
    timeline.sort(key=lambda x: x["timestamp"])

    # -------------------- ACTIVE ACCEPTED DEAL --------------------
    active_deal = next((d for d in deals if d.status == "accepted"), None)

    return render_template(
        "chat.html",
        other_user=other_user,
        timeline=timeline,
        active_deal=active_deal,
        listing_data=listing_data
    )




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

@app.route("/deal/start/<int:other_id>", methods=["POST"])
def start_deal(other_id):
    if "user_id" not in session:
        return redirect("/login")

    starter = User.query.get(session["user_id"])
    receiver = User.query.get(other_id)

    # ---------------------------
    # 1) Formdan gelen hour ve date + (opsiyonel saat)
    # ---------------------------
    hours = int(request.form["hours"])

    date_str = request.form["date"]     # "2025-12-06"
    time_str = request.form.get("time") # "14:30" olabilir veya None

    # Saat varsa birleştir → datetime objesi oluştur
    if time_str:
        date = datetime.strptime(date_str + " " + time_str, "%Y-%m-%d %H:%M")
    else:
        date = datetime.strptime(date_str, "%Y-%m-%d")

    # ---------------------------
    # 2) Chat içinde set edilmiş listing bilgisi
    # ---------------------------
    listing_id = session.get("active_listing_id")
    listing_type = session.get("active_listing_type")   # "offer" veya "need"

    # Güvenlik: listing bilgisi gelmemişse hata verme → chat’e dön
    if not listing_id or not listing_type:
        return redirect(url_for("chat", user_id=other_id))

    # ---------------------------
    # 3) Transaction nesnesi oluştur
    # ---------------------------
    t = Transaction(
        listing_type=listing_type,
        listing_id=listing_id,
        starter_id=starter.user_id,
        receiver_id=receiver.user_id,
        hours=hours,
        date=date,
        status="pending"
    )

    db.session.add(t)
    db.session.commit()

    # ---------------------------
    # 4) Mesaj ekranına doğru şekilde geri dön
    # ---------------------------
    return redirect(url_for("chat", user_id=receiver.user_id, deal_id=t.id))

@app.route("/deal/accept/<int:deal_id>", methods=["POST"])
def accept_deal(deal_id):
    deal = Transaction.query.get_or_404(deal_id)

    # sadece receiver kabul edebilir
    if session["user_id"] != deal.receiver_id:
        return redirect(url_for("chat", user_id=deal.starter_id))

    # ----------------- 1) Bu iki user arasındaki eski accepted deal'ları iptal et -----------------
    old_accepted = Transaction.query.filter(
        ((Transaction.starter_id == deal.starter_id) & (Transaction.receiver_id == deal.receiver_id)) |
        ((Transaction.starter_id == deal.receiver_id) & (Transaction.receiver_id == deal.starter_id))
    ).filter_by(status="accepted").all()

    for d in old_accepted:
        d.status = "cancelled"

    # ----------------- 2) Bu deal accepted olur -----------------
    deal.receiver_confirm = True
    deal.status = "accepted"

    db.session.commit()

    # redirect chat
    uid = session["user_id"]
    other = deal.starter_id if uid == deal.receiver_id else deal.receiver_id
    return redirect(url_for("chat", user_id=other))

@app.route("/deal/complete/<int:deal_id>", methods=["POST"])
def complete_deal(deal_id):
    if "user_id" not in session:
        return redirect("/login")

    uid = session["user_id"]
    deal = Transaction.query.get_or_404(deal_id)

    # Only accepted deals can move into completion
    if deal.status != "accepted":
        other = deal.receiver_id if uid == deal.starter_id else deal.starter_id
        return redirect(url_for("chat", user_id=other))

    # Mark user's completion confirmation
    if uid == deal.starter_id:
        deal.starter_confirm = True
    elif uid == deal.receiver_id:
        deal.receiver_confirm = True
    else:
        # Not part of the deal — block it
        other = deal.receiver_id if uid == deal.starter_id else deal.starter_id
        return redirect(url_for("chat", user_id=other))

    # If BOTH confirmed → complete!
    if deal.starter_confirm and deal.receiver_confirm:
        deal.status = "completed"
        apply_timebank_transfer(deal)

    db.session.commit()

    # Redirect to the chat with the other user
    other_user = deal.receiver_id if uid == deal.starter_id else deal.starter_id
    return redirect(url_for("chat", user_id=other_user))

@app.route("/deal/cancel_request/<int:deal_id>", methods=["POST"])
def cancel_request(deal_id):
    deal = Transaction.query.get_or_404(deal_id)
    uid = session["user_id"]

    deal.status = "cancel_pending"

    if uid == deal.starter_id:
        deal.cancel_starter_confirm = True
    else:
        deal.cancel_receiver_confirm = True

    db.session.commit()

    other = deal.receiver_id if uid == deal.starter_id else deal.starter_id
    return redirect(url_for("chat", user_id=other))

@app.route("/deal/cancel_confirm/<int:deal_id>", methods=["POST"])
def cancel_confirm(deal_id):
    deal = Transaction.query.get_or_404(deal_id)
    uid = session["user_id"]

    if uid == deal.starter_id:
        deal.cancel_starter_confirm = True
    else:
        deal.cancel_receiver_confirm = True

    # Eğer iki taraf da cancel'ı kabul ettiyse → deal iptal
    if deal.cancel_starter_confirm and deal.cancel_receiver_confirm:
        deal.status = "cancelled"

    db.session.commit()

    other = deal.receiver_id if uid == deal.starter_id else deal.starter_id
    return redirect(url_for("chat", user_id=other))


def apply_timebank_transfer(deal):
    # 1) İlan sahibini bul
    if deal.listing_type == "need":
        listing_owner_id = Need.query.get(deal.listing_id).user_id
    else:  # "offer"
        listing_owner_id = Offer.query.get(deal.listing_id).user_id

    # 2) Diğer kullanıcıyı bul (starter veya receiver'dan ilan sahibi olmayan)
    other_user_id = (
        deal.receiver_id if deal.receiver_id != listing_owner_id else deal.starter_id
    )

    listing_owner = User.query.get(listing_owner_id)
    other_user = User.query.get(other_user_id)

    # 3) Kim öder, kim kazanır?
    if deal.listing_type == "need":
        # Need ilanı: need sahibi (listing_owner) saat verir
        payer = listing_owner
        earner = other_user
    else:
        # Offer ilanı: offer sahibi (listing_owner) saat kazanır
        payer = other_user
        earner = listing_owner

    # 4) Bakiyeleri güncelle
    payer.timebank_balance -= deal.hours
    earner.timebank_balance += deal.hours

    db.session.commit()



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000,debug=True)

