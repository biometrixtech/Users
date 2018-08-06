from models._types import EnumTypeBase


class Abc(EnumTypeBase):
    name_values = {
        'a': 0,
        'b': 1,
        'c': 2
    }

def test_set_and_retrieve_values():

    abc = Abc()
    assert 0 == abc.process_bind_param('a', None)

    assert 'a' == abc.process_result_value(0, None)


