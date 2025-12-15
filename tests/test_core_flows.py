import os
from types import SimpleNamespace
import sys

os.environ["FLASK_ENV"] = "production"
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import pytest

import app as flask_app
from app import (
    Offer,
    Need,
    Transaction,
    User,
    UserBlock,
    bcrypt,
    db,
    ensure_admin_user,
)


@pytest.fixture
def client(monkeypatch):
    flask_app.app.config["TESTING"] = True
    flask_app.app.config["SQLALCHEMY_EXPIRE_ON_COMMIT"] = False

    # Avoid network calls during tests
    monkeypatch.setattr(
        flask_app,
        "geocode_with_retry",
        lambda *args, **kwargs: SimpleNamespace(latitude=41.0, longitude=29.0),
    )

    with flask_app.app.app_context():
        db.drop_all()
        flask_app.app.db_initialized = False
        db.create_all()
        ensure_admin_user()

    with flask_app.app.test_client() as client:
        yield client

    with flask_app.app.app_context():
        db.session.remove()
        db.drop_all()
        flask_app.app.db_initialized = False


def create_user(email, password="secret", balance=3, is_admin=False, is_banned=False):
    with flask_app.app.app_context():
        pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")
        user = User(
            email=email,
            password_hash=pw_hash,
            timebank_balance=balance,
            is_admin=is_admin,
            is_banned=is_banned,
        )
        db.session.add(user)
        db.session.commit()
        return SimpleNamespace(user_id=user.user_id, email=user.email)


def login_as(client, user):
    with client.session_transaction() as sess:
        sess["user_id"] = user.user_id


def test_register_and_login_sets_initial_timebank(client):
    response = client.post(
        "/register",
        data={
            "email": "user@example.com",
            "password": "secret",
            "confirm_password": "secret",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200

    with flask_app.app.app_context():
        user = User.query.filter_by(email="user@example.com").first()
        assert user is not None
        assert user.timebank_balance == 3
        assert user.password_hash != "secret"

    login_response = client.post(
        "/login",
        data={"email": "user@example.com", "password": "secret"},
        follow_redirects=True,
    )
    assert login_response.status_code == 200
    with client.session_transaction() as sess:
        assert sess["user_id"] == user.user_id

    # Duplicate registration is blocked
    duplicate = client.post(
        "/register",
        data={
            "email": "user@example.com",
            "password": "secret",
            "confirm_password": "secret",
        },
        follow_redirects=True,
    )
    assert b"already registered" in duplicate.data

    # Wrong password does not log in
    bad_login = client.post(
        "/login",
        data={"email": "user@example.com", "password": "bad"},
        follow_redirects=True,
    )
    assert b"Incorrect email or password" in bad_login.data
    with client.session_transaction() as sess:
        assert sess["user_id"] == user.user_id


def test_admin_ban_and_enforcement(client):
    with flask_app.app.app_context():
        admin_model = ensure_admin_user()
    admin = SimpleNamespace(user_id=admin_model.user_id, email=admin_model.email)
    member = create_user("member@example.com", password="secret")

    login_as(client, admin)
    ban_response = client.post(f"/admin/ban/{member.user_id}", follow_redirects=True)
    assert ban_response.status_code == 200

    with flask_app.app.app_context():
        banned_user = User.query.get(member.user_id)
        assert banned_user.is_banned is True

    with client.session_transaction() as sess:
        sess.clear()

    login_attempt = client.post(
        "/login",
        data={"email": "member@example.com", "password": "secret"},
        follow_redirects=True,
    )
    assert b"banned" in login_attempt.data
    with client.session_transaction() as sess:
        assert "user_id" not in sess

    # Enforcement during navigation also clears the session
    with client.session_transaction() as sess:
        sess["user_id"] = member.user_id
    gate_response = client.get("/", follow_redirects=False)
    assert gate_response.status_code == 403
    with client.session_transaction() as sess:
        assert "user_id" not in sess

    # Banned user cannot start deals either
    login_as(client, member)
    start_attempt = client.get(f"/start_deal/{admin.user_id}", follow_redirects=True)
    assert start_attempt.status_code == 403

    # Unban restores access
    login_as(client, admin)
    client.post(f"/admin/unban/{member.user_id}", follow_redirects=True)
    with flask_app.app.app_context():
        unbanned = User.query.get(member.user_id)
        assert unbanned.is_banned is False

    ok_login = client.post(
        "/login",
        data={"email": "member@example.com", "password": "secret"},
        follow_redirects=True,
    )
    assert ok_login.status_code == 200


def test_blocked_users_cannot_message(client):
    sender = create_user("sender@example.com")
    receiver = create_user("receiver@example.com")

    with flask_app.app.app_context():
        db.session.add(UserBlock(blocker_id=sender.user_id, blocked_id=receiver.user_id))
        db.session.commit()

    login_as(client, sender)
    resp = client.get(f"/message/{receiver.user_id}")
    assert resp.status_code == 403
    assert b"disabled between blocked users" in resp.data

    # Reverse direction is blocked too
    with client.session_transaction() as sess:
        sess["user_id"] = receiver.user_id
    resp_reverse = client.get(f"/message/{sender.user_id}")
    assert resp_reverse.status_code == 403


def test_only_owner_can_edit_or_delete_listing(client):
    owner = create_user("owner@example.com")
    stranger = create_user("stranger@example.com")

    with flask_app.app.app_context():
        offer = Offer(
            user_id=owner.user_id,
            title="Gardening",
            description="Help with garden",
            hours=2,
            location="Istanbul",
            is_active=True,
        )
        need = Need(
            user_id=owner.user_id,
            title="Tutoring",
            description="Math help",
            hours=1,
            location="Izmir",
            is_active=True,
        )
        db.session.add_all([offer, need])
        db.session.commit()
        offer_id = offer.offer_id
        need_id = need.need_id

        completed_offer_deal = Transaction(
            listing_type="offer",
            listing_id=offer.offer_id,
            starter_id=stranger.user_id,
            receiver_id=owner.user_id,
            hours=1,
            date=flask_app.datetime.utcnow(),
            status="completed",
        )
        db.session.add(completed_offer_deal)
        db.session.commit()

    login_as(client, stranger)
    forbidden = client.get(f"/offer/{offer_id}/edit")
    assert b"You cannot edit someone else's offer" in forbidden.data

    login_as(client, owner)
    locked_delete = client.post(f"/offer/{offer_id}/delete")
    assert b"cannot be deleted" in locked_delete.data

    locked_need = Transaction(
        listing_type="need",
        listing_id=need_id,
        starter_id=stranger.user_id,
        receiver_id=owner.user_id,
        hours=1,
        date=flask_app.datetime.utcnow(),
        status="completed",
    )
    with flask_app.app.app_context():
        db.session.add(locked_need)
        db.session.commit()

    cannot_edit_need = client.get(f"/need/{need_id}/edit")
    assert b"cannot be edited" in cannot_edit_need.data

    # Owner can still edit open listings
    edit_page = client.get(f"/offer/{offer_id}")
    assert edit_page.status_code == 200


def test_deal_completion_transfers_timebank_and_closes_listing(client):
    offer_owner = create_user("offer.owner@example.com", balance=6)
    requester = create_user("requester@example.com", balance=4)

    with flask_app.app.app_context():
        offer = Offer(
            user_id=offer_owner.user_id,
            title="Cooking",
            description="Cook dinner",
            hours=2,
            location="Ankara",
            is_active=True,
        )
        db.session.add(offer)
        db.session.commit()
        offer_id = offer.offer_id

        deal = Transaction(
            listing_type="offer",
            listing_id=offer.offer_id,
            starter_id=requester.user_id,
            receiver_id=offer_owner.user_id,
            hours=2,
            date=flask_app.datetime.utcnow(),
            status="accepted",
        )
        db.session.add(deal)
        db.session.commit()
        deal_id = deal.id

    login_as(client, requester)
    incomplete = client.post(
        f"/deal/complete/{deal_id}", data={"comment": "  "}, follow_redirects=True
    )
    assert incomplete.status_code == 400

    overlong = client.post(
        f"/deal/complete/{deal_id}",
        data={"comment": "x" * 251},
        follow_redirects=True,
    )
    assert overlong.status_code == 400

    first_confirmation = client.post(
        f"/deal/complete/{deal_id}", data={"comment": "Great!"}, follow_redirects=True
    )
    assert first_confirmation.status_code == 200

    login_as(client, offer_owner)
    second_confirmation = client.post(
        f"/deal/complete/{deal_id}", data={"comment": "Well done"}, follow_redirects=True
    )
    assert second_confirmation.status_code == 200

    with flask_app.app.app_context():
        refreshed_deal = Transaction.query.get(deal_id)
        updated_offer = Offer.query.get(offer_id)
        payer = User.query.get(requester.user_id)
        earner = User.query.get(offer_owner.user_id)

        assert refreshed_deal.status == "completed"
        assert updated_offer.is_active is False
        assert payer.timebank_balance == 2
        assert earner.timebank_balance == 8


def test_timebank_limits_block_overdraft_on_accept(client):
    owner = create_user("owner2@example.com", balance=10)
    requester = create_user("requester2@example.com", balance=3)

    with flask_app.app.app_context():
        need = Need(
            user_id=owner.user_id,
            title="Heavy lifting",
            description="Need help",
            hours=8,
            location="Bursa",
            is_active=True,
        )
        db.session.add(need)
        db.session.commit()
        need_id = need.need_id

        pending = Transaction(
            listing_type="need",
            listing_id=need_id,
            starter_id=owner.user_id,
            receiver_id=requester.user_id,
            hours=8,
            date=flask_app.datetime.utcnow(),
            status="pending",
        )
        db.session.add(pending)
        db.session.commit()
        pending_id = pending.id

    login_as(client, requester)
    resp = client.post(f"/deal/accept/{pending_id}")
    assert resp.status_code == 200
    assert b"exceeds timebank limits" in resp.data

    # But an affordable request can be accepted
    with flask_app.app.app_context():
        affordable = Transaction(
            listing_type="need",
            listing_id=need_id,
            starter_id=owner.user_id,
            receiver_id=requester.user_id,
            hours=2,
            date=flask_app.datetime.utcnow(),
            status="pending",
        )
        db.session.add(affordable)
        db.session.commit()
        affordable_id = affordable.id

    ok = client.post(f"/deal/accept/{affordable_id}")
    assert ok.status_code == 302  # redirect back to chat on success
#Wikidata fonksiyonu çağrılıyor mu
def test_semantic_fetch_is_called(monkeypatch, client):
    called = {"n": 0}

    def fake_fetch(q):
        called["n"] += 1
        return {"synonym"}  # önemli değil

    monkeypatch.setattr(flask_app, "fetch_wikidata_semantic_terms", fake_fetch)

    client.get("/?q=Gardening")
    assert called["n"] == 1
#Semantic terimler aramayı genişletiyor mu
def test_semantic_terms_expand_results(monkeypatch, client):
    # "plants" aramasına semantic olarak "gardening" ekleyelim
    monkeypatch.setattr(
        flask_app, "fetch_wikidata_semantic_terms", lambda q: {"gardening"}
    )

    with flask_app.app.app_context():
        listing = Offer(
            user_id=create_user("s@example.com").user_id,
            title="Gardening help",
            description="Weeding and planting",
            hours=1,
            location="Antalya",
            is_active=True,
        )
        db.session.add(listing)
        db.session.commit()

    resp = client.get("/?q=plants")
    assert resp.status_code == 200
    assert b"Gardening help" in resp.data
#semantic yokken bulunmaması
def test_without_semantic_terms_does_not_expand(monkeypatch, client):
    monkeypatch.setattr(flask_app, "fetch_wikidata_semantic_terms", lambda q: set())

    with flask_app.app.app_context():
        listing = Offer(
            user_id=create_user("s2@example.com").user_id,
            title="Gardening help",
            description="Weeding and planting",
            hours=1,
            location="Antalya",
            is_active=True,
        )
        db.session.add(listing)
        db.session.commit()

    resp = client.get("/?q=plants")
    assert resp.status_code == 200
    assert b"Gardening help" not in resp.data


def test_semantic_search_fallback_when_no_terms(monkeypatch, client):
    monkeypatch.setattr(flask_app, "fetch_wikidata_semantic_terms", lambda query: set())

    with flask_app.app.app_context():
        listing = Offer(
            user_id=create_user("searcher@example.com").user_id,
            title="Gardening help",
            description="Weeding and planting",
            hours=1,
            location="Antalya",
            is_active=True,
        )
        db.session.add(listing)
        db.session.commit()

    response = client.get("/?q=Gardening")
    assert response.status_code == 200
    assert b"Gardening help" in response.data
