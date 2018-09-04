from sqlalchemy import types

# TODO: Refactor Enums to use mixins

class EnumTypeBase(types.TypeDecorator):
    impl = types.Integer
    name_values = {}
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.reverse_look_up = dict(zip(self.name_values.values(), self.name_values.keys()))

    def process_bind_param(self, value, dialect):
        try:
            return self.name_values[value]    # Convert name to an integer
        except KeyError:
            return

    def process_result_value(self, value, dialect):
        try:
            return self.reverse_look_up[value]    # Convert an integer to a name
        except KeyError:
            return
