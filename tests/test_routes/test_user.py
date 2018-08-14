import pytest
from sqlalchemy.orm import Session
import os

from routes.user import jwt_make_payload, create_user_object, add_missing_keys, \
                        verify_user_id_matches_jwt, save_user_data, delete_user, \
                        create_sensor_mobile_pair, update_sensor_mobile_pair, \
                        retrieve_sensor_mobile_pair, delete_sensor_mobile_pair, \
                        create_authorization_resp
from db_connection import engine, Base
from models import Users, Teams, TeamsUsers #, SportsHistory  # , TrainingGroups, TrainingGroupsUsers
from routes.user import create_user_dictionary, save_sports_history, save_training_schedule, get_user
from tests.test_fixtures import example_user_data, example_user_data_2


@pytest.fixture
def session():
    session = Session(bind=engine)
    # session.begin_nested()   # TODO Figure out why data is not being saved when this is turned on even when session.close is used
    return session


def setup_module(session):
    Base.metadata.create_all(engine.connect())


def teardown_module():
    # http://alexmic.net/flask-sqlalchemy-pytest/
    # session.rollback()
    # session.close()  # Closes the transaction and commits all the changes.
    pass


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
    assert user
    teams = session.query(Teams).join(TeamsUsers).filter(TeamsUsers.user_id == user.id).all()
    # training_groups = session.query(TrainingGroups).join(TrainingGroupsUsers).filter(TrainingGroupsUsers.user_id == user.id).all()
    user_dictionary = create_user_dictionary(user)
    assert type(user_dictionary) == dict
    assert 'cleared_to_play'  in user_dictionary.keys()


def test_add_missing_keys():
    expected_user_keys = {
        "email": str,
        "password": str,
        "biometric_data": {
            "gender": str,
            "height": {"m": float},
            "mass": {"kg": float}
        },
        "personal_data": {
            "birth_date": str,
            "first_name": str,
            "last_name": str,
            "phone_number": str,
            "account_type": str,
            "account_status": str,
            "zip_code": str
        },
        "role": str,
        "system_type": str,
        "injury_status": str,
        "onboarding_status": list,
        "cleared_to_play": True
    }
    data = {"personal_data": {"Hello": "123"}}
    data = add_missing_keys(data, expected_user_keys)
    print(data)
    assert dict == type(data)


def test_create_user_object(session):

    user_object = create_user_object(example_user_data_2)
    print(type(user_object))
    assert type(user_object) == Users
    assert hasattr(user_object, 'first_name')
    session.add(user_object)
    session.commit()
    user_returned = session.query(Users).filter(Users.id == user_object.id).one()
    assert user_returned
    assert type(user_returned) == Users


def test_save_training_schedule(session):

    pass

@pytest.mark.skip # (reason="Did not finish SportsHistory module")
def test_save_sports_history(session):
    user = session.query(Users).first()
    sports_history_list = save_sports_history(example_user_data, user.id)
    assert type(sports_history_list) == list
    print(type(sports_history_list[0]))
    # assert type(sports_history_list[0]) == SportsHistory


def test_verify_user_id_matches_jwt():
    user_id = '19bfad75-9d95-4fff-aec9-de4a93da214d'
    sign_in_method = "json"
    role = 4
    # jwt_token = jwt_make_payload(user_id, sign_in_method, role)
    jwt_token = os.getenv('JWT_TOKEN')
    matching = verify_user_id_matches_jwt(jwt_token=jwt_token, user_id=user_id)
    assert matching


def test_create_user_sensor_mobile_pair(session):
    user = session.query(Users).first()
    sensor_pid = "ADFN@#L)FA)FDFNKSDF12"
    mobile_udid = "3NVAODR@)JASDFK@#KASFNSF3923nfa3"
    res = create_sensor_mobile_pair(user_id=user.id, sensor_pid=sensor_pid, mobile_udid=mobile_udid)
    print(res)
    assert type(res) == dict
    assert res['message'] == 'Success!'
    assert res['user_id'] == user.id
    assert res['sensor_pid'] == sensor_pid
    assert res['mobile_udid'] == mobile_udid


def test_retrieve_user_sensor_mobile_pair(session):
    user = session.query(Users).first()
    res = retrieve_sensor_mobile_pair(user_id=user.id)
    print(res)
    assert type(res) == dict
    assert res['message'] == 'Success!'
    assert res['user_id'] == user.id
    assert 'sensor_pid' in res
    assert 'mobile_udid' in res


def test_update_user_sensor_mobile_pair(session):
    user = session.query(Users).first()
    sensor_pid = "ZZFER11NEW11Bb"
    mobile_udid = "99DFaff39Vnf9FS44"
    res = update_sensor_mobile_pair(user_id=user.id, sensor_pid=sensor_pid, mobile_udid=mobile_udid)
    print(res)
    assert type(res) == dict
    assert res['message'] == 'Success!'
    assert res['user_id'] == user.id
    assert 'sensor_pid' in res
    assert 'mobile_udid' in res


def test_delete_user_sensor_mobile_pair(session):
    # user = session.query(Users).first()
    # user_id = user.id
    user_id = 'e562e24e-933a-4de8-a799-44bfed8d7e8d'
    res = delete_sensor_mobile_pair(user_id=user_id)
    print(res)
    assert type(res) == dict
    assert res['message'] == 'Sensor and mobile uid successfully deleted.'
    assert str(res['user_id']) == user_id
    user_updated = session.query(Users).filter(Users.id==user_id).one()
    assert user_updated.sensor_pid is None
    assert user_updated.mobile_udid is None


def test_save_user_data(session):
    user_id = 'e562e24e-933a-4de8-a799-44bfed8d7e8d'
    user = session.query(Users).filter(Users.id == user_id).one()
    user_data_update = {
        "biometric_data": {
            "height": {"m": 1.5},
            "mass": {"kg": 98}
        },
        "personal_data": {
            "phone_number": "555-123-4508",
        },
        "onboarding_status": ["account_setup"]
    }
    user_new = save_user_data(user, user_data_update)
    assert "555-123-4508" == user_new.phone_number


def test_save_user_data_2(session):
    user_id = 'e562e24e-933a-4de8-a799-44bfed8d7e8d'
    user = session.query(Users).filter(Users.id == user_id).one()
    user_data_update = {
            "email": "mazen+mvp@fathomai.com",
            "password": "Fathom123!",
            "biometric_data": {
                "gender": "male",
                "height": {"m": 1.9},
                "mass": {"kg": 102.5}
            },
            "personal_data": {
              "birth_date": "01/10/1989",
              "first_name": "Mazen",
              "last_name": "Chami",
              "phone_number": "6319889681",
              "account_type": "free",
              "account_status": "active",
              "zip_code": "27701"
            },
            "role": "athlete",
            "system_type": "1-sensor",
            "injury_status": "healthy",
            "onboarding_status": ["account_setup"]
        }
    user_new = save_user_data(user, user_data_update)
    assert "account_setup" == user_new.onboarding_status[0]
    assert "free" == user_new.account_type
    assert "active" == user_new.account_status


def test_delete_user(session):

    user_object = create_user_object(example_user_data_2)
    session.add(user_object)
    session.commit()
    user_to_be_deleted = str(user_object.id)
    auth = create_authorization_resp(user_id=user_object.id, sign_in_method='json', role=user_object.role)
    user = session.query(Users).filter(Users.id == user_to_be_deleted).one()
    res = delete_user(user.id, jwt_token=auth['jwt'])
    assert 'Success' in res['message']
    user = session.query(Users).filter(Users.id == user_to_be_deleted).first()
    assert user is None


def test_get_user(session):
    user_id = 'e562e24e-933a-4de8-a799-44bfed8d7e8d'

    user_resp = get_user(user_id)
    assert type(user_resp) == dict
    assert 'biometric_data' in user_resp['user']
    assert 'personal_data' in user_resp['user']

