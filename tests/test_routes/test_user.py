import pytest
from sqlalchemy.orm import Session

from routes.user import jwt_make_payload, create_user_object
from db_connection import engine, Base
from models import Users, Teams, TeamsUsers# , TrainingGroups, TrainingGroupsUsers
from routes.user import create_user_dictionary
from tests.test_fixtures import example_user_data

@pytest.fixture
def session():
    return Session(bind=engine)


def setup_module(session):
    Base.metadata.create_all(engine.connect())


def tear_down_module(session):

    session.rollback()
    session.close()


def test_jwt_make_payload():
    user_id = "00e1a1c9-f81e-476c-a4dc-29fabe715043"
    sign_in_method = "json"
    role = 4
    jwt_token = jwt_make_payload(user_id, sign_in_method, role)
    assert type(jwt_token) == bytes
    # print(jwt_token)


def test_create_user_dictionary(session):

    email = "glitch0@gmail.com"
    user_query = session.query(Users).filter_by(email=email)
    user = user_query.first()
    teams = session.query(Teams).join(TeamsUsers).filter(TeamsUsers.user_id == user.id).all()
    # training_groups = session.query(TrainingGroups).join(TrainingGroupsUsers).filter(TrainingGroupsUsers.user_id == user.id).all()
    user_dictionary = create_user_dictionary(user)
    assert type(user_dictionary) == dict


def test_create_user_object(session):

    user_object = create_user_object(example_user_data)
    print(type(user_object))
    assert type(user_object) == Users
    assert hasattr(user_object, 'first_name')
    session.add(user_object)
    session.commit()
