import os
import requests
import unittest


class BaseTest(unittest.TestCase):
    host = 'https://apis.dev.fathomai.com/users/latest'
    endpoint = None
    method = None
    body = None
    authorization = None
    expected_status = None

    longMessage = True

    def _get_headers(self):
        headers = {
            'Accept': 'application/json',
            'User-Agent': 'biometrix apitest',
        }
        if self.authorization is not None:
            headers['Authorization'] = self.authorization
        return headers

    def validate_response(self, body, headers, status):
        pass

    def validate_aws_pre(self):
        pass

    def validate_aws_post(self):
        pass

    def test(self):
        if self.endpoint is None:
            # Still in the base class
            self.skipTest('Base class')
            return
        endpoint = os.path.join(self.host, self.endpoint)

        self.validate_aws_pre()

        if self.method == 'GET':
            res = requests.get(endpoint, headers=self._get_headers())
        elif self.method == 'POST':
            res = requests.post(endpoint, json=self.body, headers=self._get_headers())
        elif self.method == 'PATCH':
            res = requests.patch(endpoint, json=self.body, headers=self._get_headers())
        else:
            self.fail('Unsupported method')

        expected_statuses = self.expected_status if isinstance(self.expected_status, list) else [self.expected_status]
        self.assertIn(res.status_code, expected_statuses, msg=res.json().get('message', ''))

        if 200 <= res.status_code < 300:
            self.validate_response(res.json(), res.headers, res.status_code)

        self.validate_aws_post()
