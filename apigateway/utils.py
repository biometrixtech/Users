import datetime
import uuid
from exceptions import ValueNotFoundInDatabase


def convert_to_ft_inches(distance_dictionary):
    """
    Determines which metric was provided and converts it to the height in ft and inches
    :param distance_dictionary:
    :return:
    """
    return 0, 0


def convert_to_pounds(weight_dictionary):
    """
    Determines which metric was provided and converts it to pounds
    :param weight_dictionary:
    :return:
    """
    pass


def feet_to_meters(feet, inches):
    """
    Converts feet + inches into meters
    :param feet:
    :param inches:
    :return:
    """
    if feet:
        if inches:
            return (feet + inches / 12) * 0.3048
        else:
            return feet * 0.3048
    elif inches:
        return (inches / 12) * 0.3048


def lb_to_kg(weight_lbs):
    """
    Converts pounds to kilograms.
    Handles the case where the weight is None
    :param weight_lbs:
    :return:
    """
    if weight_lbs:
        return weight_lbs * 0.453592


def format_date(date_input):
    """
    Formats a date in ISO8601 short format.
    Handles the case where the input is None
    :param date_input:
    :return:
    """
    if date_input is None:
        return None
    if isinstance(date_input, datetime.datetime):
        return date_input.strftime("%Y-%m-%d")
    else:
        for format_string in ('%Y-%m-%d', '%m/%d/%y', '%Y-%m'):
            try:
                date_input = datetime.datetime.strptime(date_input, format_string)
                return date_input.strftime("%Y-%m-%d")
            except ValueError:
                pass
        return None
        # raise ValueError('no valid date format found')


def format_datetime(date_input):
    """
    Formats a date in ISO8601 short format.
    Handles the case where the input is None
    :param date_input:
    :return:
    """
    if date_input is None:
        return None
    if not isinstance(date_input, datetime.datetime):
        date_input = datetime.datetime.strptime(date_input, "%Y-%m-%dT%H:%M:%S.%f")
    return date_input.strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_uuid4(uuid_string):
    try:
        val = uuid.UUID(uuid_string, version=4)
        # If the uuid_string is a valid hex code, but an invalid uuid4, the UUID.__init__
        # will convert it to a valid uuid4. This is bad for validation purposes.
        return val.hex == uuid_string.replace('-', '')
    except ValueError:
        # If it's a value error, then the string is not a valid hex code for a UUID.
        return False


def validate_value(session, TableObject, col_name, value):
    """
    Match the inputted value to the interest option available in the database
    :param name:
    :return: validated value matching an option in the database
    """
    valid_options = session.query(TableObject).distinct(col_name).all()
    #valid_options_list = [ for option in valid_options] # Pull the column name
    print(getattr(valid_options[0], col_name))
    for option in valid_options:
        table_value = getattr(option, col_name)
        if value.lower() == table_value.lower():
            return table_value
    raise ValueNotFoundInDatabase()
