import requests, os

# Headers:
headers = {
    "Authorization": os.getenv('JWT_TOKEN')
  }

def test_user_id_get():
    user_id = "e1d09699-5f8b-49ed-8637-35c548f9edc8"
    rv = requests.get("https://apis.dev.fathomai.com/users/user/{}".format(user_id),
                      headers=headers)
    # print(rv.text)
    assert rv.status_code == 200
