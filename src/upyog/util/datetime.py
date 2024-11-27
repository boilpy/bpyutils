# imports - compatibility imports
from __future__ import absolute_import

# imports - standard imports
import time
import datetime as dt
import math

from upyog.util._math import sign
from upyog.util.eject import ejectable

ejectable(alias = { "key": "now", "alias": "datetime.datetime.now", "imports": "datetime" })
now         = dt.datetime.now
utcnow      = dt.datetime.utcnow
ejectable(alias = { "key": "utcnow", "alias": "datetime.datetime.utcnow", "imports": "datetime" })
timedelta   = dt.timedelta
ejectable(alias = { "key": "timedelta", "alias": "datetime.datetime.timedelta", "imports": "datetime" })
datetime    = dt.datetime

today       = dt.date.today

try:
    import pytz
    timezone = pytz.timezone
except ImportError:
    pass

weekday     = dt.datetime.weekday
iso_weekday = dt.datetime.isoweekday

EPOCH       = dt.datetime(1970, 1, 1)

# @ejectable()
# def utcnow(timezone_ = None):
#     """
#         Get current UTC datetime.
#     """
#     now_ = now(dt.timezone.utc)
#     if timezone_:
#         import pytz
#         timezone_ = getattr(pytz, timezone_, "UTC")
#         now_      = now_.astimezone(timezone_)
#     return now_

@ejectable(deps = ["now"])
def tznow():
    import pytz
    return now(pytz.utc)

@ejectable()
def get_timestamp_str(format_ = '%Y-%m-%d %H:%M:%S', dtobj = None):
    """
    Get current timestamp string.

    :param format_: Python-compatible datetime format. (optional)

    Example:
        
        get_timestamp_str()
        '2021-09-15 14:24:11'
        get_timestamp_str(format_ = '%d/%m/%Y')
        '15/09/2021'
    """
    import time, datetime as dt

    now       = dtobj or time.time()

    if isinstance(now, (int, float)):
        datetime_ = dt.datetime.fromtimestamp(now)
    else:
        datetime_ = now

    string    = datetime_.strftime(format_)

    return string

def check_datetime_format(datetime, format_, raise_err = False):
    """
    Check if a given "date-string" is of the format given.

    :param datetime: Datetime string.
    :param format: Python-compatible datetime format.
    :param raise_err: Raise a `ValueError` in case the format is not compliant.

    :return: bool
    :raises: ValueError

    Example:

        check_datetime_format('2011-11-11', '%Y-%m-%d')
        True
        check_datetime_format('2011-11-11 11:12:13', '%Y-%m-%d')
        False
        check_datetime_format('2011-11-11 11:12:13', '%Y-%m-%d', raise_err = True)
        ValueError: Incorrect datetime format, expected %Y-%m-%d
    """
    try:
        dt.datetime.strptime(datetime, format_)
    except ValueError:
        if raise_err:
            raise ValueError("Incorrect datetime format, expected %s" % format_)
        else:
            return False
    
    return True

_AUTO_DATETTIME_FORMATS = [
    '%Y-%m-%d %H:%M:%S.%f%z',
    '%Y-%m-%d %H:%M:%S.%f',
    '%Y-%m-%d %H:%M:%S',
    '%Y-%m-%d %H:%M',
    '%Y-%m-%d',
    '%d-%m-%Y %H:%M:%S.%f%z',
    '%d-%m-%Y %H:%M:%S.%f',
    '%d-%m-%Y %H:%M:%S',
    '%d-%m-%Y %H:%M',
    '%d-%m-%Y',
    '%H:%M:%S.%f%z',
    '%H:%M:%S.%f',
    '%H:%M:%S',
    '%H:%M',
    '%H',
    '%Y-%m-%dT%H:%M:%S%z',
    '%Y-%m-%dT%H:%M:%S.%f%z'
]

@ejectable(globals_ = { "_AUTO_DATETTIME_FORMATS": _AUTO_DATETTIME_FORMATS })
def auto_datetime(string, raise_err = True):
    """
        Convert string to datetime object

        Args:
            string (str): The string to be converted.
            raise_err (bool): Raise an error if the string is not a valid datetime format.

        Returns:
            datetime.datetime: The datetime object.

        Example:
            >>> auto_datetime("2021-09-15 14:24:11")
            datetime.datetime(2021, 9, 15, 14, 24, 11)
            >>> auto_datetime(1631711051)
            datetime.datetime(2021, 9, 15, 14, 24, 11)
            >>> auto_datetime("2021-09-15 14:24:11", raise_err = False)
            datetime.datetime(2021, 9, 15, 14, 24, 11)
    """
    import datetime as dt
    from datetime import timezone

    if isinstance(string, dt.datetime):
        return string
    
    if isinstance(string, (int, float)):
        return dt.datetime.fromtimestamp(string, timezone.utc)

    for format_ in _AUTO_DATETTIME_FORMATS:
        try:
            return dt.datetime.strptime(string, format_)
        except ValueError:
            pass

    if raise_err:
        raise ValueError("Incorrect datetime format, expected %s" % _AUTO_DATETTIME_FORMATS)

def start_of(dt, type_):
    diff = None

    if "week" in type_:
        if type_.startswith("iso"):
            td_args = { "days" : dt.isoweekday() - 1 }
        else:
            td_args = { "days" : dt.weekday() }
        
        diff = dt - timedelta(**td_args)
    elif type_ == "year":
        diff = dt - timedelta(days = dt.timetuple().tm_yday - 1)
    else:
        raise ValueError("Invalid type: %s" % type_)

    norm = diff.replace(hour = 0, minute = 0, second = 0, microsecond = 0)

    return norm

@ejectable(as_ = "dt_add")
def add(dt, value, type_):
    if type_ == "year":
        type_ = "days"
        value = sign(value) * 365 # TODO: Handle leap years

    return dt + timedelta(**{ type_: value })

@ejectable(as_ = "dt_subtract")
def subtract(dt, value, type_):
    return add(dt, -value, type_)

def iso_weekday(dt, diff):
    return add(dt, diff, "days")

def str2timedelta(string):
    dt = auto_datetime(string)
    return timedelta(
        days    = dt.day - 1,
        hours   = dt.hour,
        minutes = dt.minute,
        seconds = dt.second,
        microseconds = dt.microsecond
    )

def format(dt, format_):
    return dt.strftime(format_)

def ts(dt):
    return time.mktime(dt.timetuple())

def human_datetime(dt, year = True):
    dt = auto_datetime(dt)

    format_ = "%b %d, "
    if year:
        format_ += "%Y "
    format_ += "%I:%M %p"

    return dt.strftime(format_)

def dt2cron(dt, **kwargs):
    dt      = auto_datetime(dt)

    string  = ""

    attrs   = [ "minute", "hour",
        { "attr": "day",   "target": "daily",   "default": True },
        { "attr": "month", "target": "monthly", "default": True },
        { "attr": "week",  "target": "weekly",  "default": True, "value": "?" },
        { "attr": "year",  "target": "yearly",  "default": True }
    ]

    n_attrs = len(attrs)
    
    for i, attr in enumerate(attrs):
        value = None

        if isinstance(attr, dict):
            target  = attr.get("target")
            default = attr.get("default", False)

            if target in kwargs and kwargs[target] or default:
                value = attr.get("value", "*")

            attr = attr["attr"]

        if not value:
            value = getattr(dt, attr, value)

            if value is not None:
                string += str(value)
            else:
                string += "*"
        else:
            string += value

        if i < n_attrs - 1:
            string += " "

    return string