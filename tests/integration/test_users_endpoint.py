import requests, os
import json
from tests.test_fixtures import example_user_data, example_user_data_2

API_URL = os.getenv("API_URL", "https://apis.dev.fathomai.com")

# Headers:
headers = {
    "Authorization": os.getenv('JWT_TOKEN')
  }


def test_user_id_get():
    print(API_URL)
    print(headers)

    user_id = "e1d09699-5f8b-49ed-8637-35c548f9edc8"
    rv = requests.get("{}/users/user/{}".format(API_URL, user_id),
                      headers=headers)
    print(rv.text)
    assert rv.status_code == 200


def test_user_sign_in():
    data = {
        "email": "glitch0@gmail.com",
        "password": "muffins1"
    }
    data = {
            "email": "susie123@smith.com",
            "password": "ABC123456"
    }
    rv = requests.post("{}/users/user/sign_in".format(API_URL),
                       headers={'content-type': 'application/json'},
                       data=json.dumps(data))
    print(rv.text)
    assert rv.status_code == 200
    assert 'user' in rv.json().keys()


def test_create_user():
    headers = {'content-type': 'application/json'}
    res = requests.post("{}/users/user/".format(API_URL),
                        headers=headers,
                        data=json.dumps(example_user_data_2)
                        )
    print(res.text)
    assert 200 == res.status_code


def test_update_user():
    headers['content-type'] = 'application/json'
    user_id = "3a07c79a-2e9f-487f-aef7-555954537e29"
    updated_user_data = {'biometric_data': {'phone_number': '23412302'},
                         'personal_data': {
                                            'height': {'ft': 1.5}
                                          },
                         }
    res = requests.put("{}/users/user/{}".format(API_URL, user_id), headers=headers,
                       data=json.dumps(updated_user_data))
    print(res.text)
    assert 200 == res.status_code
