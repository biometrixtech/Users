import pytest
from apigateway import app
import json
from .sample_data import sample_logins


LOGIN_URL = "/v1/user/sign_in"
@pytest.fixture
def client():

    client = app.test_client()
    return client


def test_sign_in(client):
    dev_login, expected_ouptut = sample_logins[0]['input'], sample_logins[0]['expected_output']

    res = client.post(LOGIN_URL,
                      headers={'content-type': 'application/json'},
                      data=json.dumps(dev_login)
                      )
    assert res.status_code == 200
    res_data = json.loads(res.data.decode())
    assert type(res_data) == dict
    print(res_data)
    assert res_data == expected_ouptut


def test_no_data(client):

    res = client.post(LOGIN_URL, headers={'content-type': 'application/json'})
    # print(res.data)
    assert res.status_code == 400


def test_no_password(client):

    res = client.post(LOGIN_URL, headers={'content-type': 'application/json'},
                      data=json.dumps({'username': 'test1234',
                                       'email': 'testaccount@gmail.com'}))
    print(res.data)
    assert res.status_code == 401


def test_incorrect_password(client):
    user_login = {
                  "email": "glitch0@gmail.com",
                  "password": "muffins1s"
                 }
    res = client.post(LOGIN_URL, headers={'content-type': 'application/json'},
                      data=json.dumps(user_login))
    print(res.data)
    assert res.status_code == 401
