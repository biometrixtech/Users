import requests, os

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
