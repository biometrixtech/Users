import sqlalchemy
from db import load_user_class


def test_load_user_class():

    Users = load_user_class()
    assert type(Users) == sqlalchemy.ext.declarative.api.DeclarativeMeta
