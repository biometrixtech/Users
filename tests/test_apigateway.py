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
    assert res_data['user'] == expected_ouptut


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
    user_id = "3a07c79a-2e9f-487f-aef7-555954537e29"
    updated_user_data = {'biometric_data': {'phone_number': '23412302'},
                         'personal_data': {
                             'height': {'ft': 1.5}
                         },
                         }
    res = client.put('/v1/user/{}'.format(user_id),
                      headers=headers,
                      data=json.dumps(updated_user_data)
                      )
    print(res.data)
    assert res.status_code == 200


def test_create_sensor_mobile_pair(client):
    headers['content-type'] = 'application/json'
    # TODO: Fix testing strategy and seed a test database with the intial correct values for testing.
    user_id = '19bfad75-9d95-4fff-aec9-de4a93da214d'  # Needs to match JWT token in environmental variable and be in database

    sensor_mobile_info = {'sensor_uid': "ERAFASDFVASHKVIAS",
                          'mobile_uid': "F3423nVA324afVJKs",
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

    sensor_mobile_info = {'sensor_uid': "ERAFASDFVASHKVIAS",
                          'mobile_uid': "F3423nVA324afVJKs",
                          # 'path': None,
                          # 'httpMethod': 'post'
                         }
    res = client.get("/users/user/{}/sensor_mobile_pair".format(user_id), headers=headers)
    print(res.data)
    data = json.loads(res.data)
    assert 200 == res.status_code
    assert data['sensor_uid'] == sensor_mobile_info['sensor_uid']
    assert data['mobile_uid'] == sensor_mobile_info['mobile_uid']

    # TODO: Add verification that the entry is in the database