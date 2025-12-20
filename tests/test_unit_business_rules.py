import os
import sys
from types import SimpleNamespace

import pytest

os.environ["FLASK_ENV"] = "production"
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import app as flask_app
from app import (
    Offer,
    Need,
    Transaction,
    User,
    UserBlock,
    allowed_file,
    apply_timebank_transfer,
    db,
    ensure_admin_user,
    get_timebank_parties,
    is_blocked_between,
    is_timebank_transfer_allowed,
)


@pytest.fixture
def app_context(monkeypatch):
    # Keep geocoding deterministic if invoked indirectly
    monkeypatch.setattr(
        flask_app,
        "geocode_with_retry",
        lambda *args, **kwargs: SimpleNamespace(latitude=41.0, longitude=29.0),
    )

    flask_app.app.config["TESTING"] = True
    flask_app.app.config["SQLALCHEMY_EXPIRE_ON_COMMIT"] = False

    with flask_app.app.app_context():
        db.drop_all()
        flask_app.app.db_initialized = False
        db.create_all()
        ensure_admin_user()
        yield
        db.session.remove()
        db.drop_all()
        flask_app.app.db_initialized = False


def create_user(email, password_hash="hashed", balance=3, is_admin=False):
    user = User(
        email=email,
        password_hash=password_hash,
        timebank_balance=balance,
        is_admin=is_admin,
    )
    db.session.add(user)
    db.session.commit()
    return SimpleNamespace(user_id=user.user_id, email=user.email)


def test_allowed_file_filters_extensions():
    assert allowed_file("photo.png") is True
    assert allowed_file("receipt.JPEG") is True
    assert allowed_file("archive.tar.gz") is False
    assert allowed_file("no_extension") is False


def test_is_blocked_between_detects_bidirectional(app_context):
    alice = create_user("alice@example.com")
    bob = create_user("bob@example.com")

    assert is_blocked_between(alice.user_id, bob.user_id) is False
    assert is_blocked_between(None, bob.user_id) is False

    db.session.add(UserBlock(blocker_id=alice.user_id, blocked_id=bob.user_id))
    db.session.commit()

    assert is_blocked_between(alice.user_id, bob.user_id) is True
    assert is_blocked_between(bob.user_id, alice.user_id) is True


def test_get_timebank_parties_role_mapping(app_context):
    offer_owner = create_user("offer-owner@example.com", balance=4)
    requester = create_user("requester@example.com", balance=6)

    need_owner = create_user("need-owner@example.com", balance=5)
    helper = create_user("helper@example.com", balance=7)

    offer = Offer(
        user_id=offer_owner.user_id,
        title="Offer",
        description="desc",
        hours=2,
        location="Ankara",
        is_active=True,
    )
    need = Need(
        user_id=need_owner.user_id,
        title="Need",
        description="desc",
        hours=2,
        location="Izmir",
        is_active=True,
    )
    db.session.add_all([offer, need])
    db.session.commit()

    offer_deal = Transaction(
        listing_type="offer",
        listing_id=offer.offer_id,
        starter_id=requester.user_id,
        receiver_id=offer_owner.user_id,
        hours=2,
        date=flask_app.datetime.utcnow(),
        status="accepted",
    )
    need_deal = Transaction(
        listing_type="need",
        listing_id=need.need_id,
        starter_id=need_owner.user_id,
        receiver_id=helper.user_id,
        hours=2,
        date=flask_app.datetime.utcnow(),
        status="accepted",
    )
    db.session.add_all([offer_deal, need_deal])
    db.session.commit()

    payer, earner = get_timebank_parties(offer_deal)
    assert payer.user_id == requester.user_id
    assert earner.user_id == offer_owner.user_id

    payer, earner = get_timebank_parties(need_deal)
    assert payer.user_id == need_owner.user_id
    assert earner.user_id == helper.user_id


def test_is_timebank_transfer_allowed_respects_limits(app_context):
    payer = create_user("payer@example.com", balance=1)
    earner = create_user("earner@example.com", balance=9)

    offer = Offer(
        user_id=earner.user_id,
        title="Offer",
        description="desc",
        hours=5,
        location="",  # location unused here
    )
    db.session.add(offer)
    db.session.commit()

    pending = Transaction(
        listing_type="offer",
        listing_id=offer.offer_id,
        starter_id=payer.user_id,
        receiver_id=earner.user_id,
        hours=2,
        date=flask_app.datetime.utcnow(),
        status="pending",
    )
    db.session.add(pending)
    db.session.commit()

    assert is_timebank_transfer_allowed(pending) is False  # payer would go negative

    pending.hours = 1
    payer_model = User.query.get(payer.user_id)
    earner_model = User.query.get(earner.user_id)
    payer_model.timebank_balance = 2
    earner_model.timebank_balance = 10
    db.session.commit()

    assert is_timebank_transfer_allowed(pending) is False  # earner would exceed max

    pending.hours = 1
    earner_model = User.query.get(earner.user_id)
    earner_model.timebank_balance = 9
    db.session.commit()

    assert is_timebank_transfer_allowed(pending) is True

    pending.listing_id = 9999
    db.session.commit()

    assert is_timebank_transfer_allowed(pending) is False  # missing listing returns False


def test_apply_timebank_transfer_commits_balances(app_context):
    payer = create_user("payer2@example.com", balance=3)
    earner = create_user("earner2@example.com", balance=5)

    need = Need(
        user_id=payer.user_id,
        title="Need",
        description="desc",
        hours=3,
        location="",
    )
    db.session.add(need)
    db.session.commit()

    deal = Transaction(
        listing_type="need",
        listing_id=need.need_id,
        starter_id=payer.user_id,
        receiver_id=earner.user_id,
        hours=2,
        date=flask_app.datetime.utcnow(),
        status="accepted",
    )
    db.session.add(deal)
    db.session.commit()

    assert is_timebank_transfer_allowed(deal) is True
    apply_timebank_transfer(deal)

    payer_model = User.query.get(payer.user_id)
    earner_model = User.query.get(earner.user_id)

    assert payer_model.timebank_balance == 1
    assert earner_model.timebank_balance == 7
