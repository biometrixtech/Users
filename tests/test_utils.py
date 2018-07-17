import pytest
from sqlalchemy.orm import Session
from models import Sport
from utils import validate_value

from db_connection import engine


@pytest.fixture
def session():
    session = Session(bind=engine)
    session.begin_nested()   # TODO Figure out why data is not being saved when this is turned on even when session.close is used
    return session


#def teardown_module(session):
#    session.close()


def test_validate_value(session):

    name = validate_value(session, Sport, 'name', 'Lacrosse')
    assert 'Lacrosse' == name
    name = validate_value(session, Sport, 'name', 'lacrosse')
    assert 'Lacrosse' == name
