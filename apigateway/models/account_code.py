import boto3
from boto3.dynamodb.conditions import Key

from fathomapi.api.config import Config

import secrets
import string
from functools import partial


class AccountCodes():
    def _get_dynamodb_resource(self):
        return boto3.resource('dynamodb').Table(Config.get('ACCOUNTCODES_DYNAMODB_TABLE_NAME'))

    def get_unused_code(self):
        try:
            # grab the first code that's unused
            kcx = Key('claimed').eq('False')
            code = self._query_dynamodb(kcx, index='claimed')
            # update this code to mark used
            self._update_dynamodb(code)
        except IndexError:
            # if no unused codes are left, generate new codes and write them before grabbing a new one
            existing_codes = self._get_existing_codes()
            new_codes = self.generate_account_codes(1000, existing_codes)
            self._update_dynamodb(new_codes, write_batch=True)
            item = self.get_unused_key()
        finally:
            return item
    def _query_dynamodb(self, kcx, limit=1, index='claimed', scan_index_forward=False, exclusive_start_key=None):
        ret = self._get_dynamodb_resource().query(
                Select='ALL_ATTRIBUTES',
                Limit=limit,
                ndexName=index,
                KeyConditionExpression=kcx,
                ScanIndexForward=scan_index_forward
                )
        return ret['Items'][0]['id']

    def _update_dynamodb(self, item, write_batch=False):
        if write_batch:
            with self._get_dynamodb_resource().batch_writer() as batch:
                for i in range(len(item)):
                    batch.put_item(
                        Item={
                            'id': item[i],
                            'claimed': 'False'
                        }
                    )
        else:
            self._get_dynamodb_resource().update_item(
                    Key={'id': item},
                    UpdateExpression='SET claimed = :val',
                    ExpressionAttributeValues={':val': True}
                    )

    def _get_existing_codes(self):
        response = self._get_dynamodb_resource.scan()
        return set([item['id'] for item in response['Items']])
    
    def generate_account_codes(self, N, existing_codes=set()):
        """
        Generate random account code of format "ABCD1234"
        """
        codes = set()
        available_strings = string.ascii_uppercase
        available_strings = available_strings.replace("O", "")
        available_numbers = string.digits
        available_numbers = available_numbers.replace("0", "")
        pickchar = partial(secrets.choice, available_strings)
        picknum = partial(secrets.choice, available_numbers)
        
        while len(codes) < N:
            codes |= {''.join([pickchar() for _ in range(4)] + [picknum() for _ in range(4)]) for _ in range(N - len(codes))}
            codes = codes - existing_codes
        return codes



