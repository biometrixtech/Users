import sqlalchemy
from db_connection import define_auto_map_base


def test_load_table_classes():
    AutoMapBase = define_auto_map_base()
    assert AutoMapBase
