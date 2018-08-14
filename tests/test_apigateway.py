import pytest
from apigateway import app
import json
from .sample_data import sample_logins
from .test_fixtures import example_user_data, example_user_data_2
import os
from aws_xray_sdk.core import patch_all, xray_recorder

LOGIN_URL = "/v1/user/sign_in"

# Headers:
headers = {
    "Authorization": os.getenv('JWT_TOKEN'),
    "content-type": "application/json",
    #"Host": None,
    #"User-Agent": None,
  }

@pytest.fixture
def client():

    client = app.test_client()
    xray_recorder.begin_segment(name='users.{}.fathomai.com'.format('test'))
    return client


def test_create_user(client):
    res = client.post('/v1/user/',
                      headers={'content-type': 'application/json'},
                      data=json.dumps(example_user_data_2))
    print(res.data)
    assert 200 == res.status_code
    res_data = json.loads(res.data.decode())
    assert type(res_data) == dict


def test_sign_in(client):
    dev_login, expected_ouptut = sample_logins[0]['input'], sample_logins[0]['expected_output']
    dev_login = {
                 "email": "steve1234@gmail.com",
                 "password": "ABC123456"
                }
    res = client.post(LOGIN_URL,
                      headers={'content-type': 'application/json'},
                      data=json.dumps(dev_login)
                      )
    if res.status_code != 200:
        print(res.status_code)
        print(res.data)
    assert 200 == res.status_code
    res_data = json.loads(res.data.decode())
    assert type(res_data) == dict
    print(res_data)
    assert 'personal_data' in res_data['user']
    assert 'biometric_data' in res_data['user']
    assert 'onboarding_status' in res_data['user']


def test_no_data(client):

    res = client.post(LOGIN_URL, headers={'content-type': 'application/json'})
    # print(res.data)
    assert res.status_code == 400


def test_no_password(client):

    res = client.post(LOGIN_URL, headers={'content-type': 'application/json'},
                      data=json.dumps({'username': 'test1234',
                                       'email': 'testaccount@gmail.com'}))
    print(res.data)
    assert res.status_code == 400


def test_incorrect_password(client):
    # TODO: Password is missing in database for this account in the test database. Need to be added.
    user_login = {
                  "email": "glitch0@gmail.com",
                  "password": "muffins1s"
                 }
    res = client.post(LOGIN_URL, headers={'content-type': 'application/json'},
                      data=json.dumps(user_login))
    print(res.data)
    assert res.status_code == 401


def test_update_user(client):
    # user_id = "3a07c79a-2e9f-487f-aef7-555954537e29"
    user_id = 'e1d09699-5f8b-49ed-8637-35c548f9edc8'
    updated_user_data = {'personal_data': {'phone_number': '23412302'},
                         'biometric_data': {
                             'height': {'ft': 1.5}
                         },
                         }
    res = client.put('/v1/user/{}'.format(user_id),
                      headers=headers,
                      data=json.dumps(updated_user_data)
                      )
    print(res.data)
    assert res.status_code == 200


def test_update_user_2(client):
    user_id = 'c4f3ba9c-c874-4687-bbb8-67633a6a6d7d'
    user_data_2 = {
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
    res = client.put('/v1/user/{}'.format(user_id),
                     headers=headers,
                     data=json.dumps(user_data_2)
                     )
    print(res.data)
    assert 200 == res.status_code
    data = json.loads(res.data)['user']
    assert "free" == data['personal_data']['account_type']
    assert "active" == data['personal_data']['account_status']
    assert "account_setup" == data['onboarding_status'][0]
    assert "1989-01-10" == data['personal_data']['birth_date']
    assert "healthy" == data['injury_status']
    assert "male" == data['biometric_data']['sex']


def test_create_sensor_mobile_pair(client):
    headers['content-type'] = 'application/json'
    # TODO: Fix testing strategy and seed a test database with the intial correct values for testing.
    user_id = '19bfad75-9d95-4fff-aec9-de4a93da214d'  # Needs to match JWT token in environmental variable and be in database

    sensor_mobile_info = {'sensor_pid': "ERAFASDFVASHKVIAS",
                          'mobile_udid': "F3423nVA324afVJKs",
                          # 'path': None,
                          # 'httpMethod': 'post'
                         }
    res = client.post("/users/user/{}/sensor_mobile_pair".format(user_id), headers=headers,
                        data=json.dumps(sensor_mobile_info))
    print(res.data)
    assert 200 == res.status_code
    # TODO: Add verification that the entry is in the database


def test_retrieve_sensor_mobile_pair(client):
    headers['content-type'] = 'application/json'
    # TODO: Fix testing strategy and seed a test database with the intial correct values for testing.
    user_id = '19bfad75-9d95-4fff-aec9-de4a93da214d'  # Needs to match JWT token in environmental variable and be in database

    sensor_mobile_info = {'sensor_pid': "ERAFASDFVASHKVIAS",
                          'mobile_udid': "F3423nVA324afVJKs",
                          # 'path': None,
                          # 'httpMethod': 'post'
                         }
    res = client.get("/users/user/{}/sensor_mobile_pair".format(user_id), headers=headers)
    print(res.data)
    data = json.loads(res.data)
    assert 200 == res.status_code
    assert data['sensor_pid'] == sensor_mobile_info['sensor_pid']
    assert data['mobile_udid'] == sensor_mobile_info['mobile_udid']

    # TODO: Add verification that the entry is in the database