class DynamodbUpdate:
    def __init__(self):
        self._add = set([])
        self._set = set([])
        self._parameter_names = []
        self._parameter_values = {}
        self._parameter_count = 0

    def set(self, field, value):
        key = self._register_parameter_name(field)
        self._set.add(f'#{key} = :{key}')
        self._parameter_values[f':{key}'] = value

    def add(self, field, value):
        key = self._register_parameter_name(field)
        self._add.add(f'#{key} = :{key}')
        self._parameter_values[f':{key}'] = value

    @property
    def update_expression(self):
        set = 'SET {}'.format(', '.join(self._set)) if len(self._set) else ''
        add = 'ADD {}'.format(', '.join(self._add)) if len(self._add) else ''
        return set + ' ' + add

    @property
    def parameter_names(self):
        return {f'#p{i}': n for i, n in enumerate(self._parameter_names)}

    @property
    def parameter_values(self):
        return self._parameter_values

    def _register_parameter_name(self, parameter_name):
        self._parameter_names.append(parameter_name)
        return 'p' + str(len(self._parameter_names) - 1)

    def __str__(self):
        return str({
            'update_expression': self.update_expression,
            'parameter_names': self.parameter_names,
            'parameter_values': self.parameter_values,
        })
