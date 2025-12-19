

from flask import (
    Flask,
    jsonify,
    flash,
    render_template,
    request,
    redirect,
    session,
    url_for,
    send_from_directory,
    abort,
)
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from sqlalchemy import or_, inspect, text
from config import ADMIN_EMAIL, ADMIN_PASSWORD, SQLALCHEMY_DATABASE_URI, SECRET_KEY
import ssl
from datetime import datetime, timedelta
import re
import requests
from sqlalchemy.exc import IntegrityError
ssl._create_default_https_context = ssl._create_unverified_context


import os
from uuid import uuid4
from werkzeug.utils import secure_filename
import time
from geopy.geocoders import Nominatim
from geopy.exc import GeocoderTimedOut, GeocoderUnavailable
from requests.exceptions import SSLError
geolocator = Nominatim(user_agent="the-hive", timeout=10)
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
            ensure_posted_at_columns()
            ensure_admin_user()
        app.db_initialized = True

def ensure_posted_at_columns():
    """Backfill schema for posted_at/offered_on/needed_on columns if existing DB lacks them."""
    inspector = inspect(db.engine)
    with db.engine.begin() as conn:
        if "offer" in inspector.get_table_names():
            has_col = any(col["name"] == "posted_at" for col in inspector.get_columns("offer"))
            if not has_col:
                conn.execute(text("ALTER TABLE offer ADD COLUMN posted_at DATETIME DEFAULT CURRENT_TIMESTAMP"))
            has_offered_on = any(col["name"] == "offered_on" for col in inspector.get_columns("offer"))
            if not has_offered_on:
                conn.execute(text("ALTER TABLE offer ADD COLUMN offered_on DATE"))

        if "need" in inspector.get_table_names():
            has_col = any(col["name"] == "posted_at" for col in inspector.get_columns("need"))
            if not has_col:
                conn.execute(text("ALTER TABLE need ADD COLUMN posted_at DATETIME DEFAULT CURRENT_TIMESTAMP"))
            has_needed_on = any(col["name"] == "needed_on" for col in inspector.get_columns("need"))
            if not has_needed_on:
                conn.execute(text("ALTER TABLE need ADD COLUMN needed_on DATE"))
@app.before_request
def enforce_ban():
    user_id = session.get("user_id")
    if not user_id:
        return

    user = User.query.get(user_id)
    if user and user.is_banned and request.endpoint not in {"logout", "login"}:
        session.clear()
        return render_template("login.html", error="Your account has been banned."), 403

from functools import wraps

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))

        user = User.query.get(user_id)
        if not user or not user.is_admin:
            return "Admin access required", 403

        return f(*args, **kwargs)

    return decorated


def is_blocked_between(user_a_id, user_b_id):
    if not user_a_id or not user_b_id:
        return False
    return UserBlock.query.filter(
        ((UserBlock.blocker_id == user_a_id) & (UserBlock.blocked_id == user_b_id)) |
        ((UserBlock.blocker_id == user_b_id) & (UserBlock.blocked_id == user_a_id))
    ).first() is not None


def get_admin_user():
    return User.query.filter_by(is_admin=True).first()


def ensure_admin_user():
    admin = get_admin_user()
    if admin:
        return admin

    password_hash = bcrypt.generate_password_hash(ADMIN_PASSWORD).decode("utf-8")
    admin = User(
        email=ADMIN_EMAIL,
        password_hash=password_hash,
        is_admin=True,
        timebank_balance=0,
    )
    db.session.add(admin)
    db.session.commit()
    return admin

# Resimler buraya kaydedilecek:
app.config["UPLOAD_FOLDER"] = os.path.join("static", "uploads")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def parse_date_field(value):
    """Parse a YYYY-MM-DD string into a date; return None on missing/invalid input."""
    if not value:
        return None

    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        return None

def geocode_with_retry(address, attempts=3):
    """Best-effort geocoding helper used for creation and on-demand lookups."""
    if not address:
        return None

    address = address.strip()

    # Online / non-geographic cases
    if address.lower() in {"online", "remote", "anywhere"}:
        return None

    # Try increasingly specific queries
    candidates = [address]
    if "turkey" not in address.lower():
        candidates.append(f"{address}, Istanbul, Turkey")
        candidates.append(f"{address}, Turkey")

    for query in candidates:
        for i in range(attempts):
            try:
                loc = geolocator.geocode(query)
                if loc:              # ← kritik satır
                    return loc
            except (GeocoderTimedOut, GeocoderUnavailable, SSLError):
                time.sleep(1.5 * (i + 1))
            except Exception:
                return None

    return None


# ---------- DATABASE MODEL ----------

class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    timebank_balance = db.Column(db.Integer, default=3)
    is_admin = db.Column(db.Boolean, default=False)
    is_banned = db.Column(db.Boolean, default=False)

    offers = db.relationship("Offer", backref="user", lazy=True)
    needs = db.relationship("Need", backref="user", lazy=True)
    favorites = db.relationship("Favorite", backref="user", lazy=True)
    need_favorites = db.relationship("NeedFavorite", backref="user", lazy=True)

    forum_posts = db.relationship("ForumPost", backref="author", lazy=True)
    forum_comments = db.relationship("ForumComment", backref="author", lazy=True)

    forum_comment_likes = db.relationship("ForumCommentLike", backref="user", lazy=True, cascade="all, delete-orphan")


class UserBlock(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    blocker_id = db.Column(db.Integer, db.ForeignKey("user.user_id"), nullable=False)
    blocked_id = db.Column(db.Integer, db.ForeignKey("user.user_id"), nullable=False)
    __table_args__ = (db.UniqueConstraint("blocker_id", "blocked_id", name="uq_block_pair"),)

class Offer(db.Model):
    offer_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.user_id"), nullable=False)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False)
    hours = db.Column(db.Integer, nullable=False)
    location = db.Column(db.String(120), nullable=True)
    is_online = db.Column(db.Boolean, default=False)
    image_filename = db.Column(db.String(255), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    posted_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    offered_on = db.Column(db.Date, nullable=True)

class Need(db.Model):
    need_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.user_id"), nullable=False)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False)
    hours = db.Column(db.Integer, nullable=False)
    location = db.Column(db.String(120), nullable=True)
    is_online = db.Column(db.Boolean, default=False)
    image_filename = db.Column(db.String(255), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    posted_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    needed_on = db.Column(db.Date, nullable=True)

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
    listing_type = db.Column(db.String(10), nullable=False,default="general")  # 'offer', 'need', 'report', 'general'
    # #----------------------DEAL MODEL-----------------------
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

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    transaction_id = db.Column(db.Integer, db.ForeignKey("transaction.id"), nullable=False)
    from_user_id = db.Column(db.Integer, db.ForeignKey("user.user_id"), nullable=False)
    to_user_id = db.Column(db.Integer, db.ForeignKey("user.user_id"), nullable=False)
    listing_type = db.Column(db.String(10), nullable=False)
    listing_id = db.Column(db.Integer, nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ForumPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.user_id"), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (
        db.Index("ix_forum_post_title", "title"),
        db.Index("ix_forum_post_content", "content"),
    )

    comments = db.relationship(
        "ForumComment",
        backref="post",
        cascade="all, delete-orphan",
        lazy=True
    )


class ForumComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey("forum_post.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.user_id"), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    likes = db.relationship(
        "ForumCommentLike",
        backref="comment",
        cascade="all, delete-orphan",
        lazy=True
    )

class ForumCommentLike(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    comment_id = db.Column(db.Integer, db.ForeignKey("forum_comment.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.user_id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint("comment_id", "user_id", name="uq_forum_comment_like"),
    )

# ---------- SEARCH & SEMANTIC HELPERS ----------

WIKIDATA_SEARCH_URL = "https://www.wikidata.org/w/api.php"
WIKIDATA_ENTITY_URL = "https://www.wikidata.org/w/api.php"
WIKIDATA_SPARQL_URL = "https://query.wikidata.org/sparql"

USER_AGENT = "TheHiveServiceApp/1.0 (community-timebank; contact=youremail@example.com)"
HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "application/json",
}
SPARQL_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "application/sparql-results+json",
}


def _collect_entity_labels(entity):
    labels = set()
    for lang in ("en", "tr"):
        label = entity.get("labels", {}).get(lang, {}).get("value")
        if label:
            labels.add(label)
    aliases = entity.get("aliases", {})
    for lang_aliases in aliases.values():
        for item in lang_aliases:
            value = item.get("value")
            if value:
                labels.add(value)
    # Keep description but VERY conservatively: only add phrases, not single generic tokens
    description = entity.get("descriptions", {}).get("en", {}).get("value")
    if description:
        parts = re.split(r"[,;]+", description)
        for p in parts:
            p = p.strip()
            # drop very short / generic parts
            if len(p) >= 8:
                labels.add(p)

    return {label.strip().lower() for label in labels if label and len(label.strip()) >= 3}

def _choose_best_search_hit(search_results, search_term):
    """
    Pick a better Wikidata entity than always taking the first result.
    Filters out non-conceptual / media / brand / platform-ish entities.
    """
    if not search_results:
        return None

    skip_keywords = [
        "database", "website", "software", "company", "organization",
        "web service", "online", "application", "platform", "record label",
        "brand", "corporation", "enterprise", "firm", "business",
        "video game", "film", "movie", "album", "song", "television", "tv series",
        "band", "musical"
    ]

    search_lower = (search_term or "").strip().lower()

    # 1) Exact label match first (and not skipped)
    for hit in search_results:
        label = (hit.get("label") or "").strip().lower()
        desc = (hit.get("description") or "").strip().lower()
        if any(k in desc for k in skip_keywords):
            continue
        if label == search_lower:
            return hit

    # 2) If single-word query, prefer single-word labels
    is_single_word = len(search_lower.split()) == 1
    if is_single_word:
        for hit in search_results:
            label = (hit.get("label") or "").strip().lower()
            desc = (hit.get("description") or "").strip().lower()
            if any(k in desc for k in skip_keywords):
                continue
            if label and len(label.split()) == 1 and (search_lower in label):
                return hit

    # 3) Otherwise, prefer label contains query (and not skipped)
    for hit in search_results:
        label = (hit.get("label") or "").strip().lower()
        desc = (hit.get("description") or "").strip().lower()
        if any(k in desc for k in skip_keywords):
            continue
        if search_lower and label and (search_lower in label):
            return hit

    # 4) Fallback: first hit
    return search_results[0]


def _collect_related_entity_ids(claims, properties):
    related_ids = set()
    for prop in properties:
        for claim in claims.get(prop, []):
            mainsnak = claim.get("mainsnak", {})
            datavalue = mainsnak.get("datavalue", {})
            if datavalue.get("type") == "wikibase-entityid":
                value = datavalue.get("value", {})
                related_id = value.get("id")
                if related_id:
                    related_ids.add(related_id)
    return related_ids


def _fetch_related_labels_via_sparql(entity_id, max_items=20):
    """Fetch broader/narrower labels connected to an entity via SPARQL."""
    if not entity_id:
        return set()

    query = f"""
        SELECT DISTINCT ?label WHERE {{
          VALUES ?target {{ wd:{entity_id} }}

          # Ontology / structure
          {{ ?item wdt:P279* ?target . }}        # subclass chain (narrower-ish)
          UNION {{ ?target wdt:P279* ?item . }}  # broader-ish
          UNION {{ ?item wdt:P361* ?target . }}  # part of chain
          UNION {{ ?target wdt:P361* ?item . }}
          UNION {{ ?target wdt:P527* ?item . }}  # has part chain
          UNION {{ ?item wdt:P527* ?target . }}

          # Service-oriented relations (from your earlier version)
          UNION {{ ?item wdt:P366 wd:{entity_id} . }}   # "use" (tools / used-for)
          UNION {{ wd:{entity_id} wdt:P3095 ?item . }}  # practiced by (roles)
          UNION {{ wd:{entity_id} wdt:P1056 ?item . }}  # product produced

          ?item rdfs:label ?label .
          FILTER(LANG(?label) IN ("en", "tr"))
        }}
        LIMIT {max_items}
        """

    try:
        response = requests.get(
            WIKIDATA_SPARQL_URL,
            params={"query": query, "format": "json"},
            headers=SPARQL_HEADERS,
            timeout=8,
        )
        response.raise_for_status()
        data = response.json()
        results = data.get("results", {}).get("bindings", [])
        labels = set()
        for item in results:
            label_val = item.get("label", {}).get("value")
            if label_val:
                labels.add(label_val.strip().lower())
        return labels
    except requests.RequestException:
        return set()

def _fetch_instance_labels_via_sparql(entity_id, max_items=50):
    """Fetch labels for items that are instances of the given entity."""
    if not entity_id:
        return set()

    query = f"""
        SELECT DISTINCT ?label WHERE {{
          ?item wdt:P31/wdt:P279* wd:{entity_id} .
          ?item rdfs:label ?label .
          FILTER(LANG(?label) IN ("en", "tr"))
        }}
        LIMIT {max_items}
        """

    try:
        response = requests.get(
            WIKIDATA_SPARQL_URL,
            params={"query": query, "format": "json"},
            headers=SPARQL_HEADERS,
            timeout=8,
        )
        response.raise_for_status()
        data = response.json()
        results = data.get("results", {}).get("bindings", [])
        labels = set()
        for item in results:
            label_val = item.get("label", {}).get("value")
            if label_val:
                labels.add(label_val.strip().lower())
        return labels
    except requests.RequestException:
        return set()

def _fetch_subclass_labels_via_sparql(entity_id, max_items=50):
    """Fetch labels for subclasses (and sub-subclasses) of the given entity."""
    if not entity_id:
        return set()

    query = f"""
    SELECT DISTINCT ?label WHERE {{
      ?item wdt:P279* wd:{entity_id} .
      ?item rdfs:label ?label .
      FILTER(LANG(?label) IN ("en","tr"))
    }}
    LIMIT {max_items}
    """

    try:
        response = requests.get(
            WIKIDATA_SPARQL_URL,
            params={"query": query, "format": "json"},
            headers=SPARQL_HEADERS,
            timeout=12,
        )
        response.raise_for_status()
        data = response.json()
        results = data.get("results", {}).get("bindings", [])
        labels = set()
        for item in results:
            v = item.get("label", {}).get("value")
            if v:
                labels.add(v.strip().lower())
        return labels
    except requests.RequestException:
        return set()


def _expand_query_tokens(query):
    base_tokens = re.findall(r"[\w']+", query.lower())
    expansions = set(base_tokens)

    prefixes = ("re", "pre", "de", "un")
    suffixes = ("ing", "ion", "tion", "s", "es", "ed", "al", "ment")

    for token in base_tokens:
        for prefix in prefixes:
            if token.startswith(prefix) and len(token) - len(prefix) >= 3:
                expansions.add(token[len(prefix) :])
        for suffix in suffixes:
            if token.endswith(suffix) and len(token) - len(suffix) >= 3:
                expansions.add(token[: -len(suffix)])

    return {t for t in expansions if len(t) >= 3}


def _fetch_entity_labels(entity_ids):
    if not entity_ids:
        return set()
    try:
        response = requests.get(
            WIKIDATA_ENTITY_URL,
            params={
                "action": "wbgetentities",
                "ids": "|".join(entity_ids),
                "format": "json",
                "languages": "en|tr",
                "props": "labels|aliases|descriptions",
            },
            headers=HEADERS,
            timeout=5,
        )
        response.raise_for_status()
        data = response.json().get("entities", {})
        labels = set()
        for entity in data.values():
            labels.update(_collect_entity_labels(entity))
        return labels
    except requests.RequestException:
        return set()


def fetch_wikidata_semantic_terms(query):
    """Return a set of semantic keywords for the query using Wikidata."""
    if not query:
        return set()

    expanded_tokens = _expand_query_tokens(query)
    terms = set(expanded_tokens)

    try:
        search_response = requests.get(
            WIKIDATA_SEARCH_URL,
            params={
                "action": "wbsearchentities",
                "search": query,
                "language": "en",
                "format": "json",
                "limit": 5,
            },
            headers=HEADERS,
            timeout=6,
        )
        print("WBSEARCH status:", search_response.status_code)
        print("WBSEARCH url:", search_response.url)
        search_response.raise_for_status()
        search_results = search_response.json().get("search", [])
        print("WBSEARCH results:", len(search_results))
        if search_results:
            print("WBSEARCH top hit:", search_results[0].get("id"), search_results[0].get("label"),
                  search_results[0].get("description"))

        if not search_results:
            return terms or {query.lower()}

        top_hit = _choose_best_search_hit(search_results, query)
        entity_id = top_hit.get("id")
        ...
        # tek entity üzerinden devam
        if not entity_id:
            return terms or {query.lower()}

        entity_response = requests.get(
            WIKIDATA_ENTITY_URL,
            params={
                "action": "wbgetentities",
                "ids": entity_id,
                "format": "json",
                "languages": "en|tr",
                "props": "labels|aliases|descriptions|claims",
            },
            headers=HEADERS,
            timeout=5,
        )
        entity_response.raise_for_status()
        entity = entity_response.json().get("entities", {}).get(entity_id, {})
        print("WBGET status:", entity_response.status_code)
        print("WBGET url:", entity_response.url)

        terms.update(_collect_entity_labels(entity))

        claims = entity.get("claims", {})
        related_ids = _collect_related_entity_ids(claims, ["P279", "P31"])

        terms.update(_fetch_entity_labels(related_ids))
        terms.update(_fetch_related_labels_via_sparql(entity_id))

        # NEW: pull instances/subclasses under the concept (helps: sport -> baseball)
        terms.update(_fetch_subclass_labels_via_sparql(entity_id, max_items=50))

        terms.add(query.lower())
        return {t for t in terms if len(t) >= 3}

    except requests.RequestException:
        fallback_terms = terms or {query.lower()}
        return fallback_terms


def build_listing_filter(model, terms):
    patterns = set()
    for term in terms:
        clean = term.strip().lower()
        if clean:
            patterns.add(clean)

    if not patterns:
        return None

    filters = []
    for pattern in patterns:
        like_pattern = f"%{pattern}%"
        filters.extend(
            [
                model.title.ilike(like_pattern),
                model.description.ilike(like_pattern),
                model.location.ilike(like_pattern),
            ]
        )

    return or_(*filters)
def _collect_listing_terms(listing):
    """Gather semantic and location-aware terms for a listing."""

    terms = set()
    title = (getattr(listing, "title", "") or "").strip()
    description = (getattr(listing, "description", "") or "").strip()
    location = (getattr(listing, "location", "") or "").strip()

    if title:
        terms.update(fetch_wikidata_semantic_terms(title))
        terms.add(title.lower())

    if description:
        for part in re.split(r"[\n\.\,;]+", description):
            part = part.strip().lower()
            if len(part) >= 4:
                terms.add(part)

    if location:
        terms.add(location.lower())

    return {t for t in terms if t}


def find_related_listings(listing, listing_type, limit=3):
    """Return a small set of related offers/needs based on content & location."""

    terms = _collect_listing_terms(listing)
    base_location = (getattr(listing, "location", "") or "").lower().strip()

    offer_query = Offer.query.filter_by(is_active=True)
    need_query = Need.query.filter_by(is_active=True)

    if listing_type == "offer":
        offer_query = offer_query.filter(Offer.offer_id != listing.offer_id)
    else:
        need_query = need_query.filter(Need.need_id != listing.need_id)

    offer_filter = build_listing_filter(Offer, terms)
    need_filter = build_listing_filter(Need, terms)

    if offer_filter is not None:
        offer_query = offer_query.filter(offer_filter)
    if need_filter is not None:
        need_query = need_query.filter(need_filter)

    candidates = [("offer", o) for o in offer_query.all()] + [
        ("need", n) for n in need_query.all()
    ]

    def score(item):
        text = f"{getattr(item, 'title', '')} {getattr(item, 'description', '')}".lower()
        s = 0
        for term in terms:
            if term and term in text:
                s += 1
        loc = (getattr(item, "location", "") or "").lower()
        if base_location and loc:
            if base_location in loc or loc in base_location:
                s += 2
        return s

    ranked = sorted(
        ((kind, obj, score(obj)) for kind, obj in candidates),
        key=lambda entry: (
            entry[2],
            getattr(entry[1], "offer_id", getattr(entry[1], "need_id", 0)),
        ),
        reverse=True,
    )

    suggestions = []
    for kind, obj, _ in ranked:
        if len(suggestions) >= limit:
            break
        suggestions.append({"type": kind, "item": obj})

    return suggestions
# ---------- ROUTES ----------

@app.route("/")
def index():
    query = request.args.get("q", "").strip()

    if query:
        terms = fetch_wikidata_semantic_terms(query)
        print("TERMS:", sorted(list(terms))[:50])
        # Cap for performance: keep query + up to 30 other terms
        terms = list(terms)
        terms = [t for t in terms if t != query.lower()]
        terms = [query.lower()] + terms[:30]
        terms = set(terms)
        offer_filter = build_listing_filter(Offer, terms)
        need_filter = build_listing_filter(Need, terms)

        offers_query = Offer.query.filter_by(is_active=True).join(User)
        needs_query = Need.query.filter_by(is_active=True).join(User)

        if offer_filter is not None:
            offers_query = offers_query.filter(offer_filter)
        if need_filter is not None:
            needs_query = needs_query.filter(need_filter)

        offers = offers_query.all()
        needs = needs_query.all()
    else:
        offers = Offer.query.filter_by(is_active=True).join(User).all()
        needs = Need.query.filter_by(is_active=True).join(User).all()

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
        search_query=query,
    )

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"].strip()

        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password_hash, password):
            if user.is_banned:
                return render_template("login.html", error="Your account has been banned.")
            session["user_id"] = user.user_id
            return redirect(url_for("index"))

        return render_template("login.html", error="Incorrect email or password.")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email")  # strip yok
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if not email or not password or not confirm_password:
            return "All fields are required."

        if password != confirm_password:
            return "Passwords do not match!"

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return "Email is already registered."

        password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
        if email == ADMIN_EMAIL:
            return "Cannot register with admin email."
        user = User(email=email, password_hash=password_hash, timebank_balance=3)

        try:
            db.session.add(user)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return "Email is already registered."

    return render_template("register.html")

@app.template_filter("mask_email")
def mask_email(email):
    """Return a privacy-friendly label instead of a raw email address."""
    if not email:
        return "Anonymous member"

    local_part = email.split("@")[0]
    if len(local_part) <= 2:
        return "Anonymous member"

    return f"{local_part[0]}***{local_part[-1]}"
@app.route("/needs")
def needs_page():
    needs = Need.query.filter_by(is_active=True).all()
    user_need_favorites = set()
    if "user_id" in session:
        need_favs = NeedFavorite.query.filter_by(user_id=session["user_id"]).all()
        user_need_favorites = {f.need_id for f in need_favs}

    return render_template("needs.html",
                           needs=needs,
                           user_need_favorites=user_need_favorites)

@app.route("/offers")
def offers_page():
    offers = Offer.query.filter_by(is_active=True).all()

    # Eğer kullanıcı giriş yaptıysa favorilerini çek
    user_favorites = set()
    if "user_id" in session:
        favs = Favorite.query.filter_by(user_id=session["user_id"]).all()
        user_favorites = {f.offer_id for f in favs}

    return render_template("offers.html", offers=offers, user_favorites=user_favorites)

@app.route("/favorites")
@login_required
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

@app.route("/forum")
def forum_index():
    q = request.args.get("q", "").strip()
    query = ForumPost.query

    if q:
        like_pattern = f"%{q}%"
        query = query.filter(
            or_(
                ForumPost.title.ilike(like_pattern),
                ForumPost.content.ilike(like_pattern),
            )
        )

    posts = query.order_by(ForumPost.created_at.desc()).all()
    return render_template("forum.html", posts=posts, q=q)

@app.route("/forum", methods=["POST"])
@login_required
def create_forum_post():
    title = request.form.get("title", "").strip()
    content = request.form.get("content", "").strip()

    if not title or not content:
        return "Title and content are required", 400

    post = ForumPost(user_id=session["user_id"], title=title, content=content)
    db.session.add(post)
    db.session.commit()

    return redirect(url_for("forum_index"))


@app.route("/forum/<int:post_id>/comment", methods=["POST"])
@login_required
def add_forum_comment(post_id):
    content = request.form.get("content", "").strip()
    if not content:
        return "Comment content is required", 400

    post = ForumPost.query.get(post_id)
    if not post:
        abort(404)

    comment = ForumComment(post_id=post.id, user_id=session["user_id"], content=content)
    db.session.add(comment)
    db.session.commit()

    return redirect(url_for("forum_index"))

@app.route("/forum/<int:post_id>/edit", methods=["POST"])
@login_required
def edit_forum_post(post_id):
    post = ForumPost.query.get_or_404(post_id)

    if post.user_id != session["user_id"]:
        abort(403)

    title = request.form.get("title", "").strip()
    content = request.form.get("content", "").strip()

    if not title or not content:
        return "Title and content are required", 400

    post.title = title
    post.content = content
    db.session.commit()

    return redirect(url_for("forum_index"))

@app.route("/forum/<int:post_id>/delete", methods=["POST"])
@login_required
def delete_forum_post(post_id):
    post = ForumPost.query.get_or_404(post_id)

    if post.user_id != session["user_id"]:
        abort(403)

    db.session.delete(post)
    db.session.commit()

    return redirect(url_for("forum_index"))


@app.route("/forum/comment/<int:comment_id>/edit", methods=["POST"])
@login_required
def edit_forum_comment(comment_id):
    comment = ForumComment.query.get_or_404(comment_id)

    if comment.user_id != session["user_id"]:
        abort(403)

    content = request.form.get("content", "").strip()
    if not content:
        return "Comment content is required", 400

    comment.content = content
    db.session.commit()

    return redirect(url_for("forum_index"))


@app.route("/forum/comment/<int:comment_id>/delete", methods=["POST"])
@login_required
def delete_forum_comment(comment_id):
    comment = ForumComment.query.get_or_404(comment_id)

    if comment.user_id != session["user_id"]:
        abort(403)

    db.session.delete(comment)
    db.session.commit()

    return redirect(url_for("forum_index"))
@app.route("/add-need", methods=["GET", "POST"])
@login_required
def add_need():
    if "user_id" not in session:
        return redirect("/login")

    if request.method == "POST":
        title = request.form["title"]
        description = request.form["description"]
        hours = int(request.form["hours"])
        needed_on_input = request.form.get("needed_on")

        # RAW USER LOCATION (strip kullanıyoruz — capitalize yok)
        location_input = request.form["location"].strip()

        # worldwide geocode (Istanbul zorlaması KALDIR)
        loc = geocode_with_retry(location_input)
        lat = loc.latitude if loc else None
        lon = loc.longitude if loc else None

        # IMAGE HANDLING
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

        # CREATE NEED ENTRY
        need = Need(
            user_id=session["user_id"],
            title=title,
            description=description,
            hours=hours,
            location=location_input,  # DİKKAT: location değil, location_input
            is_online=("online" in location_input.lower()),
            image_filename=image_filename,
            latitude=lat,
            longitude=lon,
            posted_at=datetime.utcnow(),
            needed_on=parse_date_field(needed_on_input),
        )

        db.session.add(need)
        db.session.commit()

        return redirect(url_for("index"))

    return render_template("add_need.html", today_str=datetime.utcnow().strftime("%Y-%m-%d"))

@app.route("/add-offer", methods=["GET", "POST"])
@login_required
def add_offer():
    if "user_id" not in session:
        return redirect("/login")

    if request.method == "POST":
        title = request.form["title"]
        description = request.form["description"]
        hours = int(request.form["hours"])
        location = request.form["location"].strip()
        offered_on_input = request.form.get("offered_on")

        loc = geocode_with_retry(location)
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
            longitude=lon,
            is_active=True,
            posted_at=datetime.utcnow(),
            offered_on=parse_date_field(offered_on_input),
        )

        db.session.add(offer)
        db.session.commit()

        return redirect(url_for("index"))

    return render_template("add_offer.html", today_str=datetime.utcnow().strftime("%Y-%m-%d"))


@app.route("/profile")
@login_required
def my_profile():
    if "user_id" not in session:
        return redirect("/login")

    user = User.query.get(session["user_id"])
    if not user:
        session.pop("user_id", None)
        return redirect(url_for("login"))

    # --- OFFER'lar ---
    user_offers = Offer.query.filter_by(user_id=user.user_id).all()

    active_offers = [offer for offer in user_offers if offer.is_active]
    completed_offers = [offer for offer in user_offers if not offer.is_active]

    # --- NEED'ler ---
    user_needs = Need.query.filter_by(user_id=user.user_id).all()

    active_needs = [need for need in user_needs if need.is_active]
    completed_needs = [need for need in user_needs if not need.is_active]
    comments_received = Comment.query.filter_by(to_user_id=user.user_id).order_by(
        Comment.created_at.desc()
    ).all()

    comments_with_meta = []
    listing_comments = {}

    for c in comments_received:
        listing = Offer.query.get(c.listing_id) if c.listing_type == "offer" else Need.query.get(c.listing_id)
        from_user = User.query.get(c.from_user_id)

        key = f"{c.listing_type}:{c.listing_id}"
        meta = {
            "content": c.content,
            "from_email": from_user.email if from_user else "Unknown user",
            "listing_title": listing.title if listing else "Listing removed",
            "created_at": c.created_at,
        }

        comments_with_meta.append(meta)

        listing_comments.setdefault(key, []).append(meta)

    return render_template(
        "profile.html",
        user=user,
        active_offers=active_offers,
        completed_offers=completed_offers,
        active_needs=active_needs,
        completed_needs=completed_needs,
        comments=comments_with_meta,
        listing_comments=listing_comments,
        is_owner=True,
        is_blocking = False,
        admin_viewer = user.is_admin
    )


@app.route("/profile/<int:user_id>")
def view_profile(user_id):
    user = User.query.get_or_404(user_id)
    current_user_id = session.get("user_id")
    is_blocking = False
    admin_viewer = False
    if current_user_id:
        current_user = User.query.get(current_user_id)
        admin_viewer = current_user.is_admin if current_user else False
        is_blocking = (
                UserBlock.query.filter_by(blocker_id=current_user_id, blocked_id=user.user_id).first()
                is not None
        )

    # OFFER'lar
    user_offers = Offer.query.filter_by(user_id=user_id).all()
    active_offers = [offer for offer in user_offers if offer.is_active]
    completed_offers = [offer for offer in user_offers if not offer.is_active]

    # NEED'ler
    user_needs = Need.query.filter_by(user_id=user_id).all()
    active_needs = [need for need in user_needs if need.is_active]
    completed_needs = [need for need in user_needs if not need.is_active]

    comments_received = Comment.query.filter_by(to_user_id=user.user_id).order_by(
        Comment.created_at.desc()
    ).all()

    comments_with_meta = []
    listing_comments = {}

    for c in comments_received:
        listing = Offer.query.get(c.listing_id) if c.listing_type == "offer" else Need.query.get(c.listing_id)
        from_user = User.query.get(c.from_user_id)

        key = f"{c.listing_type}:{c.listing_id}"
        meta = {
            "content": c.content,
            "from_email": from_user.email if from_user else "Unknown user",
            "listing_title": listing.title if listing else "Listing removed",
            "created_at": c.created_at,
        }

        comments_with_meta.append(meta)
        listing_comments.setdefault(key, []).append(meta)

    return render_template(
            "profile.html",
            user=user,
            active_offers=active_offers,
            completed_offers=completed_offers,
            active_needs=active_needs,
            completed_needs=completed_needs,
            comments=comments_with_meta,
            listing_comments=listing_comments,
            is_blocking=is_blocking,
            admin_viewer=admin_viewer,
        )
@app.route("/block/<int:user_id>", methods=["POST"])
@login_required
def toggle_block(user_id):
    me = session["user_id"]
    if me == user_id:
        return redirect(request.referrer or url_for("view_profile", user_id=user_id))

    User.query.get_or_404(user_id)
    existing = UserBlock.query.filter_by(blocker_id=me, blocked_id=user_id).first()
    if existing:
        db.session.delete(existing)
    else:
        db.session.add(UserBlock(blocker_id=me, blocked_id=user_id))

    db.session.commit()
    return redirect(request.referrer or url_for("view_profile", user_id=user_id))


@app.route("/admin/ban/<int:user_id>", methods=["POST"])
@admin_required
def ban_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        return "Cannot ban an admin user.", 400
    user.is_banned = True
    db.session.commit()
    return redirect(request.referrer or url_for("view_profile", user_id=user_id))


@app.route("/admin/unban/<int:user_id>", methods=["POST"])
@admin_required
def unban_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_banned = False
    db.session.commit()
    return redirect(request.referrer or url_for("view_profile", user_id=user_id))


@app.route("/report/<int:user_id>", methods=["GET", "POST"])
@login_required
def report_user(user_id):
    reporter_id = session["user_id"]
    reported = User.query.get_or_404(user_id)
    admin = ensure_admin_user()

    if request.method == "POST":
        reason = request.form.get("reason", "").strip()
        if reason:
            content = f"Report against {reported.email} (ID: {reported.user_id}): {reason}"
            report_message = Message(
                sender_id=reporter_id,
                receiver_id=admin.user_id,
                content=content,
                listing_type="report",
            )
            db.session.add(report_message)
            db.session.commit()
            return redirect(url_for("view_profile", user_id=user_id))

    return render_template("report_user.html", reported=reported)


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

    related_listings = find_related_listings(offer, "offer")

    return render_template(
        "offer_detail.html",
        offer=offer,
        user_favorites=user_favorites,
        related_listings=related_listings,
    )

@app.route("/need/<int:need_id>")
def need_detail(need_id):
    need = Need.query.get_or_404(need_id)

    user_need_favorites = set()
    if "user_id" in session:
        favs = NeedFavorite.query.filter_by(user_id=session["user_id"]).all()
        user_need_favorites = {f.need_id for f in favs}

    related_listings = find_related_listings(need, "need")

    return render_template(
        "need_detail.html",
        need=need,
        user_need_favorites=user_need_favorites,
        related_listings=related_listings,
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

def get_chat_listing_context():
    listing_id = request.args.get("listing_id", type=int) or request.form.get("listing_id", type=int)
    listing_type = (
        request.args.get("listing_type")
        or request.args.get("type")
        or request.form.get("listing_type")
        or request.form.get("type")
    )

    if listing_id and listing_type:
        session["active_listing_id"] = listing_id
        session["active_listing_type"] = listing_type

    return session.get("active_listing_id"), session.get("active_listing_type")
def build_conversation_key(other_id, listing_id=None, listing_type=None):
    """Create a stable session key for tracking chat read state."""

    normalized_type = listing_type or "general"
    normalized_id = listing_id if listing_id is not None else "general"
    return f"{other_id}:{normalized_id}:{normalized_type}"


def remember_conversation_seen(other_id, listing_id=None, listing_type=None, timestamp=None):
    """Store the last seen timestamp for a conversation in the signed session."""

    if not timestamp:
        return

    seen_map = session.get("chat_last_seen", {})
    key = build_conversation_key(other_id, listing_id, listing_type)
    seen_map[key] = timestamp.isoformat() if hasattr(timestamp, "isoformat") else str(timestamp)
    session["chat_last_seen"] = seen_map


def conversation_has_unread(other_id, listing_id=None, listing_type=None, latest_timestamp=None):
    """Return True when the latest event happened after the user's last visit."""

    if not latest_timestamp:
        return False

    seen_map = session.get("chat_last_seen", {})
    key = build_conversation_key(other_id, listing_id, listing_type)
    seen_ts = seen_map.get(key)

    if not seen_ts:
        return True

    try:
        seen_dt = datetime.fromisoformat(seen_ts)
    except ValueError:
        return True

    return latest_timestamp > seen_dt

def parse_report_message(content: str):
    """Extract report metadata from a standard report message string.

    Expected format:
    "Report against <email> (ID: <user_id>): <reason>"
    Returns a dictionary with email, user_id, and reason if parsing succeeds,
    otherwise ``None``. The parser is intentionally forgiving to account for
    missing spaces or minor formatting deviations in stored messages.
    """

    if not content:
        return None

    pattern = r"Report against\s+(.+?)\s*\(ID:\s*(\d+)\)\s*:\s*(.+)"
    match = re.search(pattern, content, flags=re.IGNORECASE)
    if not match:
        return None

    try:
        user_id = int(match.group(2))
    except ValueError:
        return None

    return {
        "email": match.group(1).strip(),
        "user_id": user_id,
        "reason": match.group(3).strip(),
    }


@app.route("/message/<int:to_user_id>", methods=["GET", "POST"])
def send_message(to_user_id):
    if "user_id" not in session:
        return redirect("/login")

    my_id = session["user_id"]
    receiver = User.query.get_or_404(to_user_id)

    if is_blocked_between(my_id, to_user_id):
        return "Messaging is disabled between blocked users.", 403
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

    if chat_messages:
        remember_conversation_seen(
            to_user_id,
            listing_id=None,
            listing_type="general",
            timestamp=chat_messages[-1].timestamp,
        )

    messages_with_meta = [
        {
            "msg": m,
            "report": parse_report_message(m.content),
        }
        for m in chat_messages
    ]

    return render_template(
        "messages.html",
        messages=messages_with_meta,
        other=receiver,
    )
# -------------------- CHAT SYSTEM --------------------

@app.route("/chat/<int:user_id>", methods=["GET", "POST"])
@login_required
def chat(user_id):
    if "user_id" not in session:
        return redirect("/login")

    me = session["user_id"]
    other = user_id
    other_user = User.query.get(other)

    if not other_user:
        return "User not found.", 404
    if is_blocked_between(me, other):
        return "Messaging is disabled between blocked users.", 403

    listing_id, listing_type = get_chat_listing_context()

    if not listing_id or not listing_type:
        # Fallback to the most recent conversation context so the chat page
        # still works even if the user refreshed without query params.
        last_msg = Message.query.filter(
            (
                ((Message.sender_id == me) & (Message.receiver_id == other)) |
                ((Message.sender_id == other) & (Message.receiver_id == me))
            ) &
            (Message.listing_id.isnot(None))
        ).order_by(Message.timestamp.desc()).first()

        if last_msg:
            session["active_listing_id"] = last_msg.listing_id
            session["active_listing_type"] = last_msg.listing_type
            listing_id = last_msg.listing_id
            listing_type = last_msg.listing_type
        else:
            return "Listing context missing. Open chat from an Offer or Need page."

    listing_id = session["active_listing_id"]
    listing_type = session["active_listing_type"]

    # -------------------- COMPLETED POST KONTROLÜ --------------------
    if listing_type == "offer":
        listing = Offer.query.get(listing_id)
    else:
        listing = Need.query.get(listing_id)

    if not listing:
        return "Listing not found for this chat."

        # Listing kapanmış olsa bile mesajlaşmaya izin veriyoruz; yeni anlaşma başlatmayı
        # şablon tarafında devre dışı bırakacağız.
    listing_closed = not listing.is_active
    # -------------------- MESAJ GÖNDER --------------------
    if request.method == "POST" and "message" in request.form:
        text = request.form["message"].strip()
        if text:
            msg = Message(
                sender_id=me,
                receiver_id=other,
                content=text,
                listing_id=listing_id,
                listing_type=listing_type
            )
            db.session.add(msg)
            db.session.commit()
        return redirect(url_for("chat", user_id=other,listing_id=listing_id,type=listing_type))

    # -------------------- MESAJLARI YÜKLE --------------------
    messages = Message.query.filter(
        (
            ((Message.sender_id == me) & (Message.receiver_id == other)) |
            ((Message.sender_id == other) & (Message.receiver_id == me))
        )
        &
        (Message.listing_id == listing_id)
        &
        (Message.listing_type == listing_type)
    ).order_by(Message.timestamp.asc()).all()

    # -------------------- DEALS --------------------
    deals = Transaction.query.filter(
        (
            (Transaction.starter_id == me) & (Transaction.receiver_id == other)
        ) |
        (
            (Transaction.starter_id == other) & (Transaction.receiver_id == me)
        )
    ).filter(
        Transaction.listing_id == listing_id,
        Transaction.listing_type == listing_type
    ).order_by(Transaction.date.asc()).all()

    timeline = []

    def build_message_entry(message_obj):
        return {
            "type": "message",
            "timestamp": message_obj.timestamp,
            "sender_id": message_obj.sender_id,
            "content": message_obj.content,
            "report": parse_report_message(message_obj.content),
        }

    for m in messages:
        timeline.append(build_message_entry(m))
    for d in deals:
        timeline.append({
            "type": "deal",
            "timestamp": d.date,
            "deal": d,
        })
    timeline.sort(key=lambda x: x["timestamp"])

    last_event_ts = timeline[-1]["timestamp"].isoformat() if timeline else ""
    if timeline:
        remember_conversation_seen(
            other,
            listing_id=listing_id,
            listing_type=listing_type,
            timestamp=timeline[-1]["timestamp"],
        )
    listing_data = {
        "type": listing_type,
        "title": listing.title,
        "hours": listing.hours,
        "location": listing.location,
        "id": listing_id
    }

    return render_template(
        "chat.html",
        other_user=other_user,
        listing=listing,
        listing_type=listing_type,
        listing_data=listing_data,
        timeline=timeline,
        listing_closed=listing_closed,
        last_event_ts=last_event_ts,
    )

@app.route("/chat/<int:user_id>/messages", methods=["GET", "POST"])
@login_required
def chat_messages(user_id):
    me = session["user_id"]
    other = user_id

    listing_id, listing_type = get_chat_listing_context()

    # If the request arrives without explicit context (e.g. after refresh),
    # reuse the latest conversation listing so polling continues to work.
    if not listing_id or not listing_type:
        last_msg = Message.query.filter(
            (
                ((Message.sender_id == me) & (Message.receiver_id == other))
                | ((Message.sender_id == other) & (Message.receiver_id == me))
            )
            & (Message.listing_id.isnot(None))
        ).order_by(Message.timestamp.desc()).first()

        if last_msg:
            listing_id = last_msg.listing_id
            listing_type = last_msg.listing_type
            session["active_listing_id"] = listing_id
            session["active_listing_type"] = listing_type

    if not listing_id or not listing_type:
        return jsonify({"error": "listing_context_missing"}), 400

    def serialize_message(msg):
        return {
            "id": msg.id,
            "sender_id": msg.sender_id,
            "receiver_id": msg.receiver_id,
            "content": msg.content,
            "timestamp": msg.timestamp.isoformat(),
            "report": parse_report_message(msg.content),
        }

    def serialize_deal(deal):
        return {
            "id": deal.id,
            "listing_type": deal.listing_type,
            "listing_id": deal.listing_id,
            "starter_id": deal.starter_id,
            "receiver_id": deal.receiver_id,
            "hours": deal.hours,
            "date": deal.date.isoformat(),
            "status": deal.status,
            "starter_confirm": deal.starter_confirm,
            "receiver_confirm": deal.receiver_confirm,
            "cancel_starter_confirm": deal.cancel_starter_confirm,
            "cancel_receiver_confirm": deal.cancel_receiver_confirm,
        }

    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        text = payload.get("message") if isinstance(payload, dict) else None
        if text is None:
            text = request.form.get("message")

        text = (text or "").strip()

        if not text:
            return jsonify({"error": "empty_message"}), 400

        msg = Message(
            sender_id=me,
            receiver_id=other,
            content=text,
            listing_id=listing_id,
            listing_type=listing_type,
        )
        db.session.add(msg)
        db.session.commit()

        return jsonify({"message": serialize_message(msg)}), 201

    after = request.args.get("after")
    include_deals = request.args.get("include_deals") in ("1", "true", "True")

    messages_query = Message.query.filter(
        (
            ((Message.sender_id == me) & (Message.receiver_id == other))
            | ((Message.sender_id == other) & (Message.receiver_id == me))
        )
        & (Message.listing_id == listing_id)
        & (Message.listing_type == listing_type)
    )
    if after:
        try:
            after_dt = datetime.fromisoformat(after)
            messages_query = messages_query.filter(Message.timestamp > after_dt)
        except ValueError:
            pass

    messages = messages_query.order_by(Message.timestamp.asc()).all()

    response_payload = {"messages": [serialize_message(m) for m in messages]}

    if include_deals:
        deals_query = Transaction.query.filter(
            (
                    (Transaction.starter_id == me) & (Transaction.receiver_id == other)
            )
            | ((Transaction.starter_id == other) & (Transaction.receiver_id == me))
        ).filter(
            Transaction.listing_id == listing_id,
            Transaction.listing_type == listing_type,
        )

        if after:
            try:
                after_dt = datetime.fromisoformat(after)
                deals_query = deals_query.filter(Transaction.date > after_dt)
            except ValueError:
                pass

        deals = deals_query.order_by(Transaction.date.asc()).all()
        response_payload["deals"] = [serialize_deal(d) for d in deals]

    return jsonify(response_payload)


@app.route("/messages")
@login_required
def messages_list():
    if "user_id" not in session:
        return redirect("/login")

    my_id = session["user_id"]

    # Konuştuğum herkesin listesi:
    other_id = db.case(
        (Message.sender_id == my_id, Message.receiver_id),
        else_=Message.sender_id
    )
    chat_conversations = (
        db.session.query(
            other_id.label("other_id"),
            User.email,
            Message.listing_id,
            Message.listing_type,
            db.func.max(Message.timestamp).label("last_time"),
            db.func.max(Message.content).label("last_message")
        )
        .join(User, User.user_id == other_id)
        .filter((Message.sender_id == my_id) | (Message.receiver_id == my_id))
        .filter(Message.listing_id.isnot(None))
        .filter(Message.listing_type.isnot(None))
        .group_by(other_id, User.email, Message.listing_id, Message.listing_type)
        .order_by(db.desc("last_time"))
        .all()
    )
    general_conversations = (
        db.session.query(
            other_id.label("other_id"),
            User.email,
            db.func.max(Message.timestamp).label("last_time"),
            db.func.max(Message.content).label("last_message"),
            db.func.max(Message.listing_type).label("listing_type"),
        )
        .join(User, User.user_id == other_id)
        .filter((Message.sender_id == my_id) | (Message.receiver_id == my_id))
        .filter(Message.listing_id.is_(None))
        .group_by(other_id, User.email)
        .order_by(db.desc("last_time"))
        .all()
    )

    def build_general_conversation(convo):
        latest_msg = (
            Message.query.filter(
                ((Message.sender_id == my_id) & (Message.receiver_id == convo.other_id))
                | ((Message.sender_id == convo.other_id) & (Message.receiver_id == my_id))
            )
            .filter(Message.listing_id.is_(None))
            .order_by(Message.timestamp.desc())
            .first()
        )

        has_notification = conversation_has_unread(
            convo.other_id,
            listing_id=None,
            listing_type=convo.listing_type or "general",
            latest_timestamp=latest_msg.timestamp if latest_msg else None,
        )
        return {
            "other_id": convo.other_id,
            "email": convo.email,
            "listing_id": None,
            "listing_type": convo.listing_type or "general",
            "last_time": latest_msg.timestamp if latest_msg else convo.last_time,
            "last_message": convo.last_message,
            "listing_title": "General conversation",
            "listing_hours": None,
            "listing_location": None,
            "has_notification": bool(has_notification),
        }

    def build_listing_conversation(convo):
        listing = (
            Offer.query.get(convo.listing_id)
            if convo.listing_type == "offer"
            else Need.query.get(convo.listing_id)
        )

        listing_title = None
        listing_hours = None
        listing_location = None

        if listing:
            listing_title = listing.title
            listing_hours = listing.hours
            listing_location = listing.location
        else:
            listing_title = f"{convo.listing_type.title()} #{convo.listing_id}"
        latest_msg = (
                Message.query.filter(
                    (
                            ((Message.sender_id == my_id) & (Message.receiver_id == convo.other_id))
                            | ((Message.sender_id == convo.other_id) & (Message.receiver_id == my_id))
                    )
                    & (Message.listing_id == convo.listing_id)
                    & (Message.listing_type == convo.listing_type)
            )
                .order_by(Message.timestamp.desc())
                .first()
        )

        latest_deal = (
            Transaction.query.filter(
                (
                        (Transaction.starter_id == my_id)
                        & (Transaction.receiver_id == convo.other_id)
                )
                |
                (
                        (Transaction.starter_id == convo.other_id)
                        & (Transaction.receiver_id == my_id)
                )
            )
            .filter(
                Transaction.listing_id == convo.listing_id,
                Transaction.listing_type == convo.listing_type,
            )
            .order_by(Transaction.date.desc())
            .first()
        )

        latest_event_time = None
        has_notification = False

        if latest_msg:
            latest_event_time = latest_msg.timestamp

        if latest_deal and (latest_event_time is None or latest_deal.date > latest_event_time):
            latest_event_time = latest_deal.date

        last_time = latest_event_time or convo.last_time

        has_notification = conversation_has_unread(
            convo.other_id,
            listing_id=convo.listing_id,
            listing_type=convo.listing_type,
            latest_timestamp=latest_event_time,
        )

        return{
            "other_id": convo.other_id,
            "email": convo.email,
            "listing_id": convo.listing_id,
            "listing_type": convo.listing_type,
            "last_time": last_time,
            "last_message": convo.last_message,
            "listing_title": listing_title,
            "listing_hours": listing_hours,
            "listing_location": listing_location,
            "has_notification": has_notification,
        }

    enriched_conversations = []
    for convo in chat_conversations:
        if not is_blocked_between(my_id, convo.other_id):
            enriched_conversations.append(build_listing_conversation(convo))

    for convo in general_conversations:
        if not is_blocked_between(my_id, convo.other_id):
            enriched_conversations.append(build_general_conversation(convo))

    enriched_conversations.sort(key=lambda c: c["last_time"] or datetime.min, reverse=True)

    return render_template("messages_list.html", conversations=enriched_conversations)

@app.route("/deal/start/<int:other_id>", methods=["POST"])
@login_required
def start_deal(other_id):
    if "user_id" not in session:
        return redirect("/login")

    starter = User.query.get(session["user_id"])
    receiver = User.query.get(other_id)

    if is_blocked_between(starter.user_id, receiver.user_id):
        return "Cannot start a deal with a blocked user.", 403

    # ---------------------------
    # 1) Form Hours + Date (+ Optional Time)
    # ---------------------------
    hours = int(request.form["hours"])
    date_str = request.form["date"]
    time_str = request.form.get("time")

    if time_str:
        date = datetime.strptime(date_str + " " + time_str, "%Y-%m-%d %H:%M")
    else:
        date = datetime.strptime(date_str, "%Y-%m-%d")

    # ---------------------------
    # 2) Listing Context
    # ---------------------------
    listing_id = request.form.get("listing_id", type=int) or session.get("active_listing_id")
    listing_type = request.form.get("listing_type") or session.get("active_listing_type")

    if not listing_id or not listing_type:
        return redirect(url_for("chat", user_id=other_id))

        # İlan tamamlandıysa yeni bir deal başlatma
    listing = Offer.query.get(listing_id) if listing_type == "offer" else Need.query.get(listing_id)
    if not listing:
        return redirect(url_for("chat", user_id=other_id))

    if not listing.is_active:
        return redirect(url_for("chat", user_id=other_id, listing_id=listing_id, type=listing_type))
    # ---------------------------
    # 3) NEW DEAL Oluştur
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
    # ⭐ 4) SYSTEM MESSAGE EKLE
    # ---------------------------
    system_message = Message(
        sender_id=starter.user_id,
        receiver_id=receiver.user_id,
        content=f"📌 Deal request started for {hours} hours.",
        listing_id=listing_id,
        listing_type=listing_type
    )
    db.session.add(system_message)
    db.session.commit()

    # ---------------------------
    # 5) CHAT’E GERİ DÖN + deal_id PARAMETRESİ EKLİ
    # ---------------------------
    return redirect(
        url_for(
            "chat",
            user_id=receiver.user_id,
            deal_id=t.id,
            listing_id=listing_id,
            type=listing_type
        )
    )

def get_timebank_parties(deal):
    """Return payer and earner users for the given deal."""
    if deal.listing_type == "need":
        listing = Need.query.get(deal.listing_id)
    else:
        listing = Offer.query.get(deal.listing_id)

    if not listing:
        return None, None

    listing_owner_id = listing.user_id
    other_user_id = deal.receiver_id if deal.receiver_id != listing_owner_id else deal.starter_id

    listing_owner = User.query.get(listing_owner_id)
    other_user = User.query.get(other_user_id)

    if deal.listing_type == "need":
        # Need ilanı: need sahibi (listing_owner) saat verir
        return listing_owner, other_user

    # Offer ilanı: offer sahibi (listing_owner) saat kazanır
    return other_user, listing_owner


def is_timebank_transfer_allowed(deal):
    payer, earner = get_timebank_parties(deal)
    if not payer or not earner:
        return False

    return (payer.timebank_balance - deal.hours >= 0) and (earner.timebank_balance + deal.hours <= 10)
@app.route("/deal/accept/<int:deal_id>", methods=["POST"])
def accept_deal(deal_id):
    deal = Transaction.query.get_or_404(deal_id)

    # sadece receiver kabul edebilir
    if session["user_id"] != deal.receiver_id:
        return redirect(url_for("chat", user_id=deal.starter_id))

    # işlem, timebank limitlerini (min 0, max 10) ihlal ediyorsa kabul etme
    if not is_timebank_transfer_allowed(deal):
            return "Transaction cannot be accepted because it exceeds timebank limits."
    # ----------------- 1) Bu iki user arasındaki eski accepted deal'ları iptal et -----------------
    old_accepted = Transaction.query.filter(
        ((Transaction.starter_id == deal.starter_id) & (Transaction.receiver_id == deal.receiver_id)) |
        ((Transaction.starter_id == deal.receiver_id) & (Transaction.receiver_id == deal.starter_id))
    ).filter_by(status="accepted").all()

    for d in old_accepted:
        d.status = "cancelled"

    # ----------------- 2) Bu deal accepted olur -----------------
    deal.status = "accepted"
    deal.starter_confirm = False
    deal.receiver_confirm = False

    db.session.commit()

    # redirect chat
    uid = session["user_id"]
    other = deal.starter_id if uid == deal.receiver_id else deal.receiver_id
    return redirect(
        url_for(
            "chat",
            user_id=other,
            listing_id=deal.listing_id,
            type=deal.listing_type
        )
    )
@app.route("/deal/complete/<int:deal_id>", methods=["POST"])
def complete_deal(deal_id):
    if "user_id" not in session:
        return redirect("/login")

    uid = session["user_id"]
    deal = Transaction.query.get_or_404(deal_id)

    # Sadece deal'ın iki tarafı bu route'u kullanabilir
    if uid not in (deal.starter_id, deal.receiver_id):
        return redirect("/messages")

    # Sadece accepted deal tamamlanabilir
    if deal.status != "accepted":
        other = deal.receiver_id if uid == deal.starter_id else deal.starter_id
        return redirect(
            url_for(
                "chat",
                user_id=other,
                listing_id=deal.listing_id,
                type=deal.listing_type
            )
        )

    # Yorum zorunluluğu
    comment_text = request.form.get("comment", "").strip()
    if not comment_text:
        return "Please add a comment (max 250 characters) before completing the deal.", 400

    if len(comment_text) > 250:
        return "Comment exceeds 250 character limit.", 400

    # Aynı kullanıcının aynı anlaşma için birden fazla yorum yazmasını engelle
    existing_comment = Comment.query.filter_by(
        transaction_id=deal.id, from_user_id=uid
    ).first()

    if existing_comment:
        return "You have already submitted a comment for this deal.", 400

    other_user_id = deal.receiver_id if uid == deal.starter_id else deal.starter_id

    new_comment = Comment(
        transaction_id=deal.id,
        from_user_id=uid,
        to_user_id=other_user_id,
        listing_type=deal.listing_type,
        listing_id=deal.listing_id,
        content=comment_text,
    )

    db.session.add(new_comment)
    # Kullanıcı onayını işaretle
    if uid == deal.starter_id:
        deal.starter_confirm = True
    else:
        deal.receiver_confirm = True

    starter_ok = bool(deal.starter_confirm)
    receiver_ok = bool(deal.receiver_confirm)
    both_confirmed = starter_ok and receiver_ok

    # ----- İKİ TARAFTA ONAY VARSA TAMAMLA -----
    if both_confirmed and deal.status != "completed":
        if not is_timebank_transfer_allowed(deal):
            return "Transaction cannot be completed because it exceeds timebank limits."
        apply_timebank_transfer(deal)
        deal.status = "completed"

        # İlanı kapat
        if deal.listing_type == "offer":
            offer = Offer.query.get(deal.listing_id)
            if offer:
                offer.is_active = False

        elif deal.listing_type == "need":
            need = Need.query.get(deal.listing_id)
            if need:
                need.is_active = False
    db.session.commit()

    # Chat ekranına geri dön
    other_user = deal.receiver_id if uid == deal.starter_id else deal.starter_id
    return redirect(
        url_for(
            "chat",
            user_id=other_user,
            listing_id=deal.listing_id,
            type=deal.listing_type
        )
    )

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
    return redirect(
        url_for(
            "chat",
            user_id=other,
            listing_id=deal.listing_id,
            type=deal.listing_type
        )
    )
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
    payer, earner = get_timebank_parties(deal)

    payer.timebank_balance -= deal.hours
    earner.timebank_balance += deal.hours

    db.session.commit()
@app.route("/offer/<int:offer_id>/edit", methods=["GET", "POST"])
def edit_offer(offer_id):
    if "user_id" not in session:
        return redirect("/login")

    offer = Offer.query.get_or_404(offer_id)

    # Sadece sahibi editleyebilir
    if offer.user_id != session["user_id"]:
        return "You cannot edit someone else's offer."

    # Eğer COMPLETED bir deal varsa → edit yasak
    completed = Transaction.query.filter_by(
        listing_id=offer_id,
        listing_type="offer",
        status="completed"
    ).first()

    if completed:
        return "This offer has a completed deal and cannot be edited."

    # Edit işlemi
    if request.method == "POST":

        # 1) metin alanlarını güncelle
        offer.title = request.form["title"]
        offer.hours = request.form["hours"]
        offer.location = request.form["location"].strip()
        offer.description = request.form["description"]
        offer.offered_on = parse_date_field(request.form.get("offered_on"))

        # 2) image güncelleme logic’i
        file = request.files.get("image")
        if file and allowed_file(file.filename):

            # Var olan resmi sil
            if offer.image_filename:
                old_path = os.path.join(app.config["UPLOAD_FOLDER"], offer.image_filename)
                if os.path.exists(old_path):
                    os.remove(old_path)

            # Yeni resmi kaydet
            filename = secure_filename(str(uuid4()) + "_" + file.filename)
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

            offer.image_filename = filename  # DB field update

        # 3) TÜM GÜNCELLEMELERDEN SONRA COMMIT
        db.session.commit()

        return redirect(url_for("offer_detail", offer_id=offer_id))

    return render_template(
        "add_offer.html",
        offer=offer,
        editing=True,
        today_str=datetime.utcnow().strftime("%Y-%m-%d"),
    )

@app.route("/offer/<int:offer_id>/delete", methods=["POST"])
def delete_offer(offer_id):
    if "user_id" not in session:
        return redirect("/login")

    offer = Offer.query.get_or_404(offer_id)

    if offer.user_id != session["user_id"]:
        return "You cannot delete someone else's offer."

    # COMPLETED deal varsa → delete yasak
    completed = Transaction.query.filter_by(
        listing_id=offer_id,
        listing_type="offer",
        status="completed"
    ).first()

    if completed:
        return "This offer has a completed deal and cannot be deleted."

    db.session.delete(offer)
    db.session.commit()
    return redirect(url_for("my_profile"))

@app.route("/need/<int:need_id>/edit", methods=["GET", "POST"])
def edit_need(need_id):
    if "user_id" not in session:
        return redirect("/login")

    need = Need.query.get_or_404(need_id)

    # sadece sahibi editebilir
    if need.user_id != session["user_id"]:
        return "You cannot edit someone else's need."

    # completed deal kontrolü
    completed = Transaction.query.filter_by(
        listing_id=need_id,
        listing_type="need",
        status="completed"
    ).first()

    if completed:
        return "This need has a completed deal and cannot be edited."

    # POST → update işlemi
    if request.method == "POST":

        # 1) metin alanlarını güncelle
        need.title = request.form["title"]
        need.hours = request.form["hours"]
        need.location = request.form["location"].strip()
        need.description = request.form["description"]
        need.needed_on = parse_date_field(request.form.get("needed_on"))
        # 2) image güncelleme logic’i
        file = request.files.get("image")
        if file and allowed_file(file.filename):

            # eski resmi sil
            if need.image_filename:
                old_path = os.path.join(app.config["UPLOAD_FOLDER"], need.image_filename)
                if os.path.exists(old_path):
                    os.remove(old_path)

            # yeni resmi kaydet
            filename = secure_filename(str(uuid4()) + "_" + file.filename)
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

            # DB’de filename’i güncelle
            need.image_filename = filename

        # 3) commit
        db.session.commit()

        return redirect(url_for("need_detail", need_id=need_id))

    # GET → edit formu
    return render_template(
        "add_need.html",
        need=need,
        editing=True,
        today_str=datetime.utcnow().strftime("%Y-%m-%d"),
    )
@app.route("/need/<int:need_id>/delete", methods=["POST"])
def delete_need(need_id):
    if "user_id" not in session:
        return redirect("/login")

    need = Need.query.get_or_404(need_id)

    if need.user_id != session["user_id"]:
        return "You cannot delete someone else's need."

    completed = Transaction.query.filter_by(
        listing_id=need_id,
        listing_type="need",
        status="completed"
    ).first()

    if completed:
        return "This need has a completed deal and cannot be deleted."

    db.session.delete(need)
    db.session.commit()
    return redirect(url_for("my_profile"))

#burası debug için
import socket, os

@app.get("/__debug")
def __debug():
    rules = sorted(r.rule for r in app.url_map.iter_rules())
    return {
        "host": socket.gethostname(),
        "port": os.getenv("PORT"),
        "has_profile": "/profile" in rules,
        "rules_sample": rules[:30],
        "rules_count": len(rules),
        "session_user_id": session.get("user_id"),
    }


#debug sonu
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001,debug=True)

