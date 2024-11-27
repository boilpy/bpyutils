# pylint: disable=E1101
from functools import partial

# imports - compatibility imports
from upyog import _compat
from upyog._compat import iteritems, Mapping
from upyog.util._dict import dict_from_list, dict_items, dict_keys, dict_values
from upyog.util.datetime import auto_datetime
from upyog.util.check import check_array
from upyog.util.eject import ejectable

# imports - standard imports
import sys
import inspect

def get_function_arguments(fn):
    """Get arguments of a function

    Args:
        fn (function): The function to retrieve arguments from.

    Returns:
        dict: A dictionary of arguments. If there is no default argument, the value 
        associated to that argument would be inpsect._empty.

    Example

        >>> def add(a = 0, b = 1):
                return a + b
        >>> params = upy.get_function_arguments(add)
        >>> params
        {'a': 0, 'b': 1}
    """
    # https://stackoverflow.com/a/2677263
    params  = dict()
    success = False
    
    if _compat.PY2: # pragma: no cover
        argspec_getter = inspect.getargspec
        success        = True
    if _compat.PYTHON_VERSION >= (3,0) and _compat.PYTHON_VERSION < (3,5): # pragma: no cover
        argspec_getter = inspect.getfullargspec
        success        = True

    if success: # pragma: no cover
        argspec   = argspec_getter(fn)
        params    = dict_from_list(argspec.args, argspec.defaults or [])

    if _compat.PYTHON_VERSION >= (3,5):
        signature  = inspect.signature(fn)
        parameters = signature.parameters

        params     = { k: v.default for k, v in _compat.iteritems(parameters) }

        success    = True

    if not success: # pragma: no cover
        raise ValueError("Unknown Python Version {} for fetching functional arguments.".format(sys.version))

    return params

# def _str_to_bool(x):
#     if x in ("True", "true"):
#         return True
    
#     if x in ("False", "false"):
#         return False
    
#     if x in ("None", "none", "Null", "null", "NULL", ""):
#         return None

#     return x

@ejectable(deps = ["dict_items"])
def str2bool(x, raise_err = True):
    """
    Convert a string to a boolean.

    :param x: The string to be converted.

    Example::

        >>> str2bool("True")
        True
        >>> str2bool("False")
        False
    """
    _map = {
        True: ("True", "true"), False: ("False", "false"),
        None: ("None", "null", "NULL")
    }

    for k, v in dict_items(_map):
        if x in v:
            return k
        
    if raise_err:
        raise ValueError("Invalid boolean value: {}".format(x))

@ejectable(deps = ["str2bool", "auto_datetime"])
def auto_typecast(value):
    """
    Automatically convert a string into its desired data type.

    :param value: The value to be converted.

    Example::
        >>> auto_typecast("True")
        True
        >>> auto_typecast("1.2345")
        1.2345
    """
    for type_ in (str2bool, int, float, auto_datetime):
        try:
            return type_(value)
        except (KeyError, ValueError, TypeError):
            pass

    return value

@ejectable()
def gen2seq(gen, type_ = list):
    """
        Convert a Generator to a Sequence.

        Args:
            gen (generator): The generator to be converted.
            type_ (type): The type of the sequence to be converted to.

        Returns:
            type_: The sequence.

        Example::
            >>> array_filter = gen2seq(filter)
            >>> arr     = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
            >>> array_filter(lambda x: x % 2 == 0, arr)
            [0, 2, 4, 6, 8]
    """
    def fn(*args, **kwargs):
        return type_(gen(*args, **kwargs))
    return fn

@ejectable(deps = ["check_array"])
def filter2(fn, arr, other = False):
    """
        Filter a List.

        Args:
            fn (function): The function to filter the array.
            arr (list): The array to be filtered.
            other (bool): If True, returns a tuple of filtered and other elements.

        Returns:
            list: The filtered list.

        Example::
            >>> filter2(lambda x: x > 2, [1, 2, 3, 4, 5])
            [3, 4, 5]
            >>> filter2(lambda x: x > 2, [1, 2, 3, 4, 5], other = True)
            ([3, 4, 5], [1, 2])
    """
    if not callable(fn):
        if check_array(fn, raise_err = False):
            l  = fn
            fn = lambda x: x not in l
        else:
            f  = fn
            fn = lambda x: x != f

    filtered, others = [], []
    for x in arr:
        if fn(x):
            filtered.append(x)
        else:
            others.append(x)
    
    if other:
        return (filtered, others)
    else:
        return filtered

@ejectable(deps = ["gen2seq", "filter2"])
def array_filter(fn, arr, other = False):
    """
        Filter a List that returns a Sequence.

        Args:
            fn (function): The function to filter the array.
            arr (list): The array to be filtered.
            other (bool): If True, returns a tuple of filtered and other elements.

        Returns:
            list: The filtered list.

        Example::
            >>> array_filter(lambda x: x > 2, [1, 2, 3, 4, 5])
            [3, 4, 5]
            >>> array_filter(lambda x: x > 2, [1, 2, 3, 4, 5], other = True)
            ([3, 4, 5], [1, 2])
    """
    return gen2seq(filter2)(fn, arr, other = other)

@ejectable(deps = ["gen2seq"])
def lmap(fn, arr):
    return gen2seq(map)(fn, arr)

@ejectable(deps = ["gen2seq"])
def lset(arr):
    return gen2seq(set)(arr)

@ejectable()
def build_fn(fn, *args, **kwargs):
    """Build a function caller with default arguments.

    Args:
        fn (function): The function to be called.

    Returns:
        function: A function wrapper with default arguments passed.

    Example:
        
        >>> def add(a, b):
                return a + b
        >>> fn = upy.build_fn(add, a = 1, b = 2)
        >>> fn()
        3
    """
    from functools import partial
    return partial(fn, *args, **kwargs)

@ejectable()
def classname(obj):
    """
    Get the name of a class.

    :param obj: The object to get the name of.

    Example::

        classname("Hello World")
        'str'
        classname(1)
        'int'
    """
    return obj.__class__.__name__

@ejectable()
def is_num_like(x):
    """
    Check if an object is numeric.

    :param x: The object to be checked.

    Example::

        is_num_like(1)
        True
        is_num_like("Hello World")
        False
        is_num_like("1")
        True
    """
    if isinstance(x, str):
        return x.isdigit()
    elif isinstance(x, (int, float)):
        return True
    
    return False

@ejectable()
def is_dict_like(x):
    """
    Check if an object is a dictionary.

    :param x: The object to be checked.

    Example::

        is_dict_like({ "foo": "bar" })
        True
        is_dict_like([1, 2, 3])
        False
    """
    from collections.abc import Mapping
    return isinstance(x, Mapping)

@ejectable()
def ordered(x):
    if isinstance(x, dict):
        return sorted((k, ordered(v)) for k, v in iteritems(x))
    elif isinstance(x, list):
        return sorted(ordered(v) for v in x)
    
    return x

@ejectable()
def to_object(d):
    class O(object):
        pass

    params = O()

    for k, v in iteritems(d):
        setattr(params, k, v)

    return params

@ejectable(deps = ["dict_keys", "dict_values"])
def combinations(options):
    import itertools
    return [
        dict(zip(dict_keys(options), value))
            for value in itertools.product(*dict_values(options))
    ]