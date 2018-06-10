import pytest
from sqlalchemy.orm import Session

from routes.user import jwt_make_payload
from db_connection import engine
from models import Users, Teams, TeamsUsers# , TrainingGroups, TrainingGroupsUsers
from routes.user import create_user_dictionary


@pytest.fixture
def session():
    return Session(bind=engine)


def test_jwt_make_payload():
    user_id = "00e1a1c9-f81e-476c-a4dc-29fabe715043"
    sign_in_method = "json"
    role = 4
    jwt_token = jwt_make_payload(user_id, sign_in_method, role)
    assert type(jwt_token) == bytes
    # print(jwt_token)


def test_create_user_dictionary():

    email = "glitch0@gmail.com"
    user_query = session.query(Users).filter_by(email=email)
    user = user_query.first()
    teams = session.query(Teams).join(TeamsUsers).filter(TeamsUsers.user_id == user.id).all()
    # training_groups = session.query(TrainingGroups).join(TrainingGroupsUsers).filter(TrainingGroupsUsers.user_id == user.id).all()
    user_dictionary = create_user_dictionary(user)
    assert type(user_dictionary) == dict


def test_get_athlete_permissions():
    expected_resp = {'permissions':
                     {'current_user': 1234,
                      'athlete_list': [
                                       {'user': 1, 'access_level': 'view'},
                                       {'user': 2, 'access_level': 'view'},
                                       {'user': 3, 'access_level': 'view'},
                                      ]
                     }
                   }
