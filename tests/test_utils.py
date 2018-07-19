import pytest
from sqlalchemy.orm import Session
from models import Sport
from utils import validate_value, convert_to_ft_inches, convert_to_pounds

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


def test_convert_to_ft_inches():
    height_conversions = [( (6, 0), { 'm': 1.8288 })]
    for meters, ft_in in height_conversions:
        result = convert_to_ft_inches(ft_in)
        assert meters == result


def test_convert_to_pounds():
    weight_conversions = [(2.204624, {'kg': 1 })]
    for expected_lbs, kg in weight_conversions:
        result = convert_to_pounds(kg)
        assert expected_lbs == result
