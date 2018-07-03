import requests, os
import json
from tests.test_fixtures import example_user_data

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


def test_create_user():

    res = requests.post("{}/users/user".format(API_URL), headers=headers,
                        data=json.dumps(example_user_data))
    print(res.text)
    assert res.status_code == 200
