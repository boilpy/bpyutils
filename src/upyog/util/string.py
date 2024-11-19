# imports - standard imports
import re
import uuid

from upyog._compat import urlparse, iteritems
from upyog.util.array import sequencify
from upyog.util.eject import ejectable

_REGEX_ANSI_ESCAPE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
_REGEX_HTML        = re.compile("<.*?>")

@ejectable()
def strip(string, type_ = " \n"):
    import unicodedata

    string = unicodedata.normalize("NFKD", string)

    string = string.lstrip(type_)
    string = string.rstrip(type_)

    return string

def strip_ansi(string):
    string = _REGEX_ANSI_ESCAPE.sub("", string)
    return string

def pluralize(string, count = 1):
    # A very shitty pluralizer
    if not string.endswith("s"):
        if count > 1:
            string += "s"
    
    return string

def labelize(string):
    result   = ""
    upperize = False

    if string.isupper():
        string = string.lower()

    for i, char in enumerate(string):
        if char.isupper() and i > 0:
            result += " "
        elif char == "_":
            result  += " "
            upperize = True
            continue

        if upperize:
            char = char.upper()
            upperize = False

        result += char

    return result.title()

@ejectable()
def kebab_case(string, delimiter = " ", to_lower = True):
    words = string.replace(delimiter, " ").split()
    kebab = "-".join([word.lower() if to_lower else word for word in words])
    
    return kebab

@ejectable()
def camel_case(string, delimiter = " ", to_lower = True):
    words = string.replace(delimiter, " ").split()

    camel = words[0].lower() if to_lower else words[0]

    camel = camel + "".join([word.title() for word in words[1:]])

    return camel

@ejectable()
def snake_case(string):
    import re
    result = re.sub("([A-Z])", "_\\1", string).lower()
    return result

@ejectable()
def safe_encode(obj, encoding = "utf-8"):
    try:
        obj = obj.encode(encoding)
    except (AttributeError, UnicodeEncodeError):
        pass
    
    return obj

@ejectable()
def safe_decode(obj, encoding = "utf-8"):
    try:
        obj = obj.decode(encoding)
    except (AttributeError, UnicodeDecodeError):
        pass
    
    return obj

def sanitize_html(html):
    sanitized = re.sub(_REGEX_HTML, "", html)
    return sanitized

def is_ascii(string):
    try:
        string.encode("ascii")
    except UnicodeEncodeError:
        return False
    else:
        return True

def sanitize_text(text):
    text = text.replace("&nbsp;", " ")
    text = strip(text)
    return text

def sanitize(string, encoding = "utf-8"):
    string = safe_decode(string, encoding = encoding)
    string = strip(string)
    string = strip(string, type_ = " ")
    string = strip_ansi(string)
    string = sanitize_html(string)
    string = sanitize_text(string)
    return string

@ejectable()
def upper(text):
    """
        Convert text to uppercase

        Args:
            text (str): The text to be converted.

        Returns:
            str: The converted text.

        Example:
            >>> upper("hello")
            "HELLO"
            >>> upper("hello world")
            "HELLO WORLD"
            >>> upper("hello world!")
            "HELLO WORLD!"
            >>> upper("HELLO")
            "HELLO"
    """
    text = text.upper()
    return text

@ejectable()
def lower(text, only = None):
    text = text.lower()
    return text

@ejectable()
def capitalize(text):
    text = text.capitalize()
    return text

@ejectable()
def ellipsis(string, threshold = 50, pattern = "..."):
    length      = len(string)
    expected    = threshold + len(pattern) 

    if length > expected:
        string = string[:expected]
        string = "%s%s" % (string, pattern)

    return string

@ejectable()
def get_random_str(length = None, remove_hyphens = True):
    import uuid

    uuid_   = uuid.uuid4()
    string  = str(uuid_)

    if remove_hyphens:
        string  = string.replace("-", "")

    if length:
        string = string[:length]

    return string

def check_url(s, raise_err = True):
    is_url = False
    
    try:
        result = urlparse(s)
        is_url = all([result.scheme, result.netloc])
    except:
        pass
    
    if not is_url and raise_err:
        raise ValueError("Invalid URL: %s" % s)

    return is_url

@ejectable()
def nl(s = "", space = 1):
    space = "\n" * space
    return "%s%s" % (s, space)

def to_html(s):
    s = s.replace("\n", "<br>")
    return s

@ejectable()
def tb(s = "", point = 2, type_ = " "):
    indent = type_ * point
    return "%s%s" % (indent, s)

@ejectable()
def encapsulate(s, q, r = None):
    if r is None:
        r = q
    return "%s%s%s" % (q, s, r)

@ejectable()
def charsplit(s, split = "\n"):
    return s.split(split)

@ejectable()
def format2(s, *args, **kwargs):
    for k, v in iteritems(kwargs):
        s = s.replace("{{%s}}" % k, v)
    return s

@ejectable()
def replace(s, old, new):
    return s.replace(old, new)