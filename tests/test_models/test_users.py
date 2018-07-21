import pytest
from models import Users
from sqlalchemy.orm import Session
from db_connection import engine, Base
from datetime import datetime

@pytest.fixture
def session():
    session = Session(bind=engine)
    session.begin_nested()
    return session


def setup_module(session):
    Base.metadata.create_all(engine.connect())


def tear_down_module(session):
    session.rollback()
    # session.close()  # Closes the transaction and commits all the changes.


def test_create_user_object(session):

    user = Users(created_at=datetime.now(),
                 updated_at=datetime.now(),
                 email="samsmith@1234.com",
                 first_name="Sam",
                 injury_status="healthy")
    assert type(user) == Users
    session.add(user)
    session.commit()
