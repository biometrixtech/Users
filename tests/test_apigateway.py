import pytest
from apigateway import app
import json
from .sample_data import sample_logins

@pytest.fixture
def client():

    client = app.test_client()
    return client


def test_sign_in(client):
    dev_login, expected_ouptut = sample_logins[0]['input'], sample_logins[0]['expected_output']

    res = client.post('/v1/user/sign_in',
                      headers={'content-type': 'application/json'},
                      data=json.dumps(dev_login)
                      )
    assert res.status_code == 200
    res_data = json.loads(res.data.decode())
    assert type(res_data) == dict
    print(res_data)
    assert res_data == expected_ouptut
