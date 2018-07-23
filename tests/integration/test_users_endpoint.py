import requests, os
import json
from tests.test_fixtures import example_user_data, example_user_data_2

API_URL = os.getenv("API_URL", "https://apis.dev.fathomai.com")
# API_URL = os.getenv("API_URL", "https://apis.production.fathomai.com")

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
    # data = {
    #         "email": "amina@biometrixtech.com",
    #         "password": "Fathom123!"
    # }
    # data = {
    #          "email": "tests000008@biometrixtech.com",
    #          "password": "Fathom123!"
    #        }
    # data = {
    #          "email": "chrisp+athlete@biometrixtech.com",
    #          "password": ""
    # }
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


def test_create_sensor_mobile_pair():
    """
    Verifies the endpoint creates a new entry in the users_sensors_mobiles table
    :return:
    """
    headers['content-type'] = 'application/json'
    # user_id = '3a07c79a-2e9f-487f-aef7-555954537e29'  # Needs to match JWT token above
    user_id = '19bfad75-9d95-4fff-aec9-de4a93da214d'
    sensor_mobile_info = {'sensor_uid': "ERAFASDFVASHKVIAS",
                          'mobile_uid': "F3423nVA324afVJKs"
                          }
    # Login First to receive valid jwt
    # dev_login = {
    #     "email": "steve1234@gmail.com",
    #     "password": "ABC123456"
    # }
    # res = requests.post(LOGIN_URL,
    #                   headers={'content-type': 'application/json'},
    #                   data=json.dumps(dev_login)
    #                   )
    # jwt_token = res.data['authorization']['jwt']
    # user_id = res.data['user']['id']
    # headers['Authorization'] = jwt_token

    res = requests.post("{}/users/user/{}/sensor_mobile_pair".format(API_URL, user_id), headers=headers,
                        data=json.dumps(sensor_mobile_info))
    print(res.text)
    assert 200 == res.status_code
    # TODO: Add verification that the entry is in the database


def test_retrieve_sensor_mobile_pair():
    headers['content-type'] = 'application/json'
    user_id = '19bfad75-9d95-4fff-aec9-de4a93da214d'  # Needs to match JWT token above
    res = requests.get("{}/users/user/{}/sensor_mobile_pair".format(API_URL, user_id), headers=headers)
    print(res.text)
    assert 200 == res.status_code
    data = res.json()
    assert 'sensor_mobile_pair_id' in data.keys()


def test_update_sensor_mobile_pair():
    headers['content-type'] = 'application/json'
    user_id = '19bfad75-9d95-4fff-aec9-de4a93da214d'  # Needs to match JWT token above
    sensor_mobile_info = {'sensor_uid': "avn30vat0Vas",
                          'mobile_uid': "vaLFJ20Vnv59Da"
                          }
    res = requests.put("{}/users/user/{}/sensor_mobile_pair".format(API_URL, user_id), headers=headers,
                       data=json.dumps(sensor_mobile_info)
                       )
    print(res.text)
    assert 200 == res.status_code


def test_delete_sensor_mobile_pair():
    headers['content-type'] = 'application/json'
    user_id = '19bfad75-9d95-4fff-aec9-de4a93da214d'  # Needs to match JWT token above
    sensor_mobile_info = {'sensor_mobile_pair_id': "2342nvasdfk324a"  # Needs to be an existing pair id
                          }
    res = requests.delete("{}/users/user/{}/sensor_mobile_pair".format(API_URL, user_id), headers=headers,
                       data=json.dumps(sensor_mobile_info)
                       )
    print(res.text)
    assert 200 == res.status_code
    # TODO: Verify it was deleted.
