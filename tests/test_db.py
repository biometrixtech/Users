import sqlalchemy
from db import load_table_classes, define_auto_map_base, hello


def test_load_table_classes():

    Users, Teams = load_table_classes(AutoMapBase=define_auto_map_base())
    assert type(Users) == sqlalchemy.ext.declarative.api.DeclarativeMeta


def test_hello():
    hello()