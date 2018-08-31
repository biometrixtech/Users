import datetime
import uuid


def metres_to_ftin(metres):
    """
    Converts a height from metres to feet and inches
    :param metres:
    :return:
    """
    if metres is None:
        return None, None
    inches = float(metres) / 0.0254
    return inches // 12, round(inches % 12, 1)


def kg_to_lb(mass_kg):
    """
    Convert a kilogram value to pounds
    :param mass_kg:
    :return:
    """
    return round(float(mass_kg) / 0.453592, 1) if mass_kg is not None else None


def ftin_to_metres(feet, inches):
    """
    Converts feet + inches into metres
    :param feet:
    :param inches:
    :return:
    """
    if inches is None:
        return None
    inches = float(inches) + int(feet) * 12
    return round(float(inches) * 0.0254, 3)


def lb_to_kg(mass_lbs):
    """
    Converts pounds to kilograms.
    Handles the case where the input is None
    :param mass_lbs:
    :return:
    """
    return round(float(mass_lbs) * 0.453592, 3) if mass_lbs is not None else None


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
        for format_string in ('%Y-%m-%d', '%m/%d/%y', '%m/%d/%Y', '%Y-%m'):
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
