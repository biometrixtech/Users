import unittest
from utils import ftin_to_metres, metres_to_ftin


def data_provider(data):
    """Data provider decorator, allows another callable to provide the data for the test"""
    def test_decorator(fn):
        def repl(self, *args):
            for datum in data:
                try:
                    fn(self, *datum)
                except AssertionError:
                    print("Error with data set ", datum)
                    raise
        return repl
    return test_decorator


class TestFtinToMetres(unittest.TestCase):
    tests = [
        ((0, 0), 0),
        ((0, 1), 0.025),
        ((1, 0), 0.305),
        ((1, 1), 0.330),
        ((0, 2), 0.051),
        ((2, 0), 0.610),
        ((2, 2), 0.660),
    ]

    @data_provider(tests)
    def test(self, input, output):
        self.assertEqual(output, ftin_to_metres(*input))
