from ._entity import Entity, flatten
from abc import abstractmethod
from boto3.dynamodb.conditions import Key, ConditionExpressionBuilder
from botocore.exceptions import ClientError
from decimal import Decimal
from dynamodbupdate import DynamodbUpdate
from functools import reduce
from operator import iand

from exceptions import NoSuchEntityException, DuplicateEntityException, NoUpdatesException


class DynamodbEntity(Entity):

    def _fetch(self):
        # And together all the elements of the primary key
        kcx = reduce(iand, [Key(k).eq(v) for k, v in self.primary_key.items()])
        res = self._query_dynamodb(kcx)

        if len(res) == 0:
            raise NoSuchEntityException()
        print(res[0])
        return res[0]

    def patch(self, body, create=False):
        self.validate('PUT' if create else 'PATCH', body)
        body = flatten(body)

        try:
            upsert = DynamodbUpdate()
            for key in self.get_fields(immutable=None if create else False, primary_key=False):
                if key in body:
                    if self._fields[key]['type'] in ['list', 'object']:
                        upsert.add(key, set(body[key]))
                    elif self._fields[key]['type'] == 'number':
                        upsert.set(key, Decimal(str(body[key])))
                    else:
                        upsert.set(key, body[key])

            print(upsert)
            if len(upsert.parameter_values) == 0:
                raise NoUpdatesException()

            self._get_dynamodb_resource().update_item(
                Key=self.primary_key,
                UpdateExpression=upsert.update_expression,
                ExpressionAttributeNames=upsert.parameter_names,
                ExpressionAttributeValues=upsert.parameter_values,
            )
            # TODO include conditional check if create=False

            return self.get()

        except ClientError as e:
            if 'ConditionalCheckFailed' in str(e):
                raise DuplicateEntityException()
            else:
                print(str(e))
                raise

    def create(self, body):
        self.patch(body, True)
        return self.primary_key

    @abstractmethod
    def _get_dynamodb_resource(self):
        raise NotImplementedError

    def _query_dynamodb(self, key_condition_expression, limit=10000, scan_index_forward=True, exclusive_start_key=None):
        self._print_condition_expression(key_condition_expression)
        if exclusive_start_key is not None:
            ret = self._get_dynamodb_resource().query(
                Select='ALL_ATTRIBUTES',
                Limit=limit,
                KeyConditionExpression=key_condition_expression,
                ExclusiveStartKey=exclusive_start_key,
                ScanIndexForward=scan_index_forward,
            )
        else:
            ret = self._get_dynamodb_resource().query(
                Select='ALL_ATTRIBUTES',
                Limit=limit,
                KeyConditionExpression=key_condition_expression,
                ScanIndexForward=scan_index_forward,
            )
        if 'LastEvaluatedKey' in ret:
            # There are more records to be scanned
            return ret['Items'] + self._query_dynamodb(key_condition_expression, limit, scan_index_forward, ret['LastEvaluatedKey'])
        else:
            # No more items
            return ret['Items']

    @staticmethod
    def _print_condition_expression(expression):
        print(ConditionExpressionBuilder().build_expression(expression, True))