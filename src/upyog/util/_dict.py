import collections

from upyog._compat import iteritems, Mapping, iterkeys, itervalues
from upyog.util.eject import ejectable
from upyog.util.check import check_array
import upyog as upy

@ejectable(deps = ["dict_items"])
def merge_deep(dest, source):
    """
        Merge Dictionaries Deeply. `merge_deep` will override keys from right to left.

        Args:
            source (dict): Source dictionary.
            dest (dict): Destination dictionary.

        Returns:
            dict: Merged dictionary.

        Example::
            >>> merge_deep({ 'foo': { 'bar': 'baz' } }, { 'foo': { 'baz': 'boo' } })
            {'foo': {'bar': 'baz', 'baz': 'boo'}}
    """
    # https://stackoverflow.com/a/20666342
    for key, value in dict_items(source):
        if isinstance(value, dict):
            node = dest.setdefault(key, {})
            dest[key] = merge_deep(node, value)
        else:
            dest[key] = source[key]

    return dest

@ejectable(deps = ["merge_deep"])
def merge_dict(*args, **kwargs):
    """
    Merge Dictionaries.

    Args:
        args: arguments of dictionaries to be merged. `merge_dict` will override keys from right to left.

    Returns:
        dict: Merged dictionary.

    Example:
        >>> merge_dict({ 'foo': 'bar' }, { 'bar': 'baz' }, { 'baz': 'boo' })
        {'foo': 'bar', 'bar': 'baz', 'baz': 'boo'}
        >>> merge_dict({ 'foo': 'bar' }, { 'foo': 'baz', 'bar': 'boo' })
        {'foo': 'baz', 'bar': 'boo'}
    """
    deep = kwargs.get("deep", False)

    merged = dict()

    for arg in args:
        copy = arg.copy()

        if deep:
            merged = merge_deep(merged, copy)
        else:
            merged.update(copy)

    return merged

@ejectable(deps = ["check_array"])
def dict_from_list(keys, values = None):
    """
    Generate a dictionary from a list of keys and values.
    You can also use this function to generate a dictionary from a list of dictionaries.

    Args:
        keys (list): A list of keys.
        values (list, str): A list of values. If `values` is a string, it will be used as the key to generate the dictionary.

    Returns:
        dict: A dictionary.

    Example::
        >>> dict_from_list(['a', 'b', 'c'], [1, 2, 3])
        {'a': 1, 'b': 2, 'c': 3}
        >>> dict_from_list([{'name': 'foo'}, {'name': 'bar'}], 'name')
        {'foo': {'name': 'foo'}, 'bar': {'name': 'bar'}}
        >>> dict_from_list(['a', 'b', 'c'])
        {'a': None, 'b': None, 'c': None}
        >>> dict_from_list(['a', 'b', 'c'], 1)
        {'a': 1, 'b': 1, 'c': 1}
    """
    import functools

    if isinstance(values, str):
        arr = keys
        key = values

        return functools.reduce(
            lambda a, b: a.update({ b[key]: b }) or a,
            arr, {}
        )

    n_keys = len(keys)

    if not values:
        values = [None]   * n_keys

    if not check_array(values, raise_err = False):
        values = [values] * n_keys

    return dict(zip(keys, values))

@ejectable(imports = ["collections"])
class AutoDict(collections.defaultdict):
    __repr__ = dict.__repr__

@ejectable(deps = ["dict_items", "AutoDict"])
def autodict(*args, **kwargs):
    """
    Automatically adds a key to a dictionary.

    Args:
        args: arguments of dictionaries to be merged.
        dict_type (type): The type of the dictionary.
    
    Returns:
        dict: A dictionary.

    Example::
        >>> d = autodict()
        >>> d['foo']['bar']['baz'] = 'boo'
        {'foo': {'bar': {'baz': 'boo'}}}

        >>> d = autodict({ 'foo': 'bar' })
        >>> d['foo']['bar']['baz'] = 'boo'
        {'foo': {'bar': {'baz': 'boo'}}}
    """
    from collections.abc import Mapping

    dict_type = kwargs.pop("dict_type", dict)

    _autodict = AutoDict(autodict)
    update    = dict_type(*args, **kwargs)

    for key, value in dict_items(update):
        if isinstance(value, Mapping):
            value = autodict(value)
        
        _autodict.update({
            key: value
        })
    
    return _autodict

@ejectable()
def lkeys(d):
    """
    Get the keys of a dictionary as a list.

    :param d: A dictionary.

    :returns: list

    Example::

        lkeys({ 'foo': 'bar', 'baz': 'boo' })
        ['foo', 'baz']
    """
    return list(iterkeys(d))

@ejectable()
def lvalues(d):
    """
    Get the values of a dictionary as a list.

    :param d: A dictionary.

    :returns: list

    Example::

        lvalues({ 'foo': 'bar', 'baz': 'boo' })
        ['bar', 'boo']
    """
    return list(itervalues(d))

@ejectable()
def litems(d):
    """
    Get the items of a dictionary as a list.

    :param d: A dictionary.

    :returns: list

    Example::

        litems({ 'foo': 'bar', 'baz': 'boo' })
        [('foo', 'bar'), ('baz', 'boo')]
    """
    return list(iteritems(d))

@ejectable(deps = ["dict_items"])
def check_dict_struct(d, struct, raise_err = True):
    """
    Check if a dictionary has a certain structure.

    :param d: A dictionary.
    :param struct: A dictionary with the structure to be checked.
    :param raise_err: Whether to raise an error if the structure is not found.

    :returns: bool

    :raises: ValueError

    :Example:

        check_dict_struct({ "foo": { "bar": "baz" } }, { "foo": { "bar": str } })
        True
        check_dict_struct({ "foo": { "bar": "baz" } }, { "foo": { "bar": int } }, raise_err = False)
        False
    """
    if not isinstance(d, dict):
        if raise_err:
            raise ValueError("The first argument must be a dictionary.")
        else:
            return False

    if not isinstance(struct, dict):
        if raise_err:
            raise ValueError("The second argument must be a dictionary.")
        else:
            return False

    for key, value in dict_items(struct):
        if key not in d:
            if raise_err:
                raise ValueError("The key '%s' is not in the dictionary." % key)
            else:
                return False

        if isinstance(value, dict):
            if not check_dict_struct(d[key], value, raise_err):
                return False
        else:
            check = True

            if callable(value) and not value(d[key]):
                if raise_err:
                    raise ValueError("The value of the key '%s' does not satisfy the condition." % key)
                check = False
            if not isinstance(d[key], value):
                if raise_err:
                    raise ValueError("The value of the key '%s' is not of type '%s'." % (key, value))
                check = False
            
            if not check:
                return False

    return d

def is_subdict(a, b):
    sub_dict = True

    for key in iterkeys(b):
        if key in a:
            if a[key] != b[key]:
                sub_dict = False
                break

    return sub_dict

@ejectable()
# TODO: raise exception if key not found
def getattr2(d, key, default = None):
    keys  = key.split(".")

    value = d

    for key in keys:
        if value and isinstance(value, dict) and key in value:
            value = value[key]
        elif hasattr(value, key):
            value = getattr(value, key)
        else:
            value = None

    return value if value != None else default

@ejectable(deps = ["getattr2"])
def hasattr2(d, key):
    return getattr2(d, key, "__missing__") != "__missing__"

@ejectable()
def setattr2(d, key, value):
    copy = d.copy()
    keys = key.split(".")

    for key in keys[:-1]:
        if key not in d:
            copy[key] = {}

        copy = copy[key]

    copy[keys[-1]] = value

    return copy

@ejectable()
def reverse_dict(d):
    return { value: key for key, value in iteritems(d) }

_TYPE_LIST_LIKE = (list, tuple, set, frozenset)

@ejectable()
def common_dict(a, b):
    _TYPE_LIST_LIKE = (list, tuple, set, frozenset)

    a_keys = set(iterkeys(a))
    b_keys = set(iterkeys(b))

    common = {}

    common_keys = a_keys & b_keys
    
    for key in common_keys:
        i, j = a[key], b[key]

        if isinstance(i, Mapping) and isinstance(j, Mapping):
            common[key] = common_dict(i, j)
        elif isinstance(i, _TYPE_LIST_LIKE) and isinstance(j, _TYPE_LIST_LIKE):
            common[key] = list(set(i) & set(j))
        else:
            if i == j:
                common[key] = i

    return common

@ejectable()
def subtract_dict(a, b):
    _TYPE_LIST_LIKE = (list, tuple, set, frozenset)

    a_keys = set(iterkeys(a))
    b_keys = set(iterkeys(b))
    
    subtract = {}
    
    intersect_keys = a_keys.intersection(b_keys)
    subtract_keys = a_keys - b_keys
    all_keys = set(list(intersect_keys) + list(subtract_keys))
    
    for key in all_keys:
        i = a[key]
    
        if isinstance(i, Mapping):
            subtract[key] = subtract_dict(i, {})
        elif isinstance(i, _TYPE_LIST_LIKE):
            if key in b and isinstance(i, _TYPE_LIST_LIKE):
                type_ = type(i)
                i = type_(set(i) - set(b[key]))
                if i:
                    subtract[key] = i
        else:
            if key in b and i != b[key]:
                subtract[key] = i
    
    return subtract

@ejectable()
def pretty_dict(d, sep = ", "):
    s = []

    for key, value in iteritems(d):
        s.append("%s: %s" % (key, value))

    return f"{sep}".join(s)

@ejectable()
def param_dict(arg, auto_cast = True):
    output = {}

    if arg:
        params = arg.split(";")

        
        for param in params:
            key, value = param.split("=")
            key   = upy.strip(key)

            value = upy.strip(value)
            value = upy.lmap(
                upy.strip, value.split(",")
            )
            value = upy.squash(value)

            if auto_cast:
                if upy.is_list_like(value):
                    value = upy.lmap(upy.auto_typecast, value)
                else:
                    value = upy.auto_typecast(value)

            output[key] = value

    return output

@ejectable()
def pop(d, keys, default = None, raise_err = False):
    copy = d.copy()
    vals = []

    for key in keys:
        try:
            vals = copy.pop(key)
        except KeyError:
            if raise_err:
                raise KeyError(f"Key '{key}' not found in dictionary.")
            vals.append(default)

    return copy, vals

@ejectable()
def magic_dict(*args, **kwargs):
    class AttrDict(dict):
        def __init__(self, *args, **kwargs):
            super_ = super(AttrDict, self)
            super_.__init__(*args, **kwargs)
            self.__dict__ = self

    return AttrDict(*args, **kwargs)

@ejectable()
def dict_keys(d):
    return d.keys()

@ejectable()
def dict_values(d):
    return d.values()

@ejectable()
def dict_items(d):
    return d.items()

@ejectable()
def dict_filter(d, fn = lambda k, v: v):
    filtered = {}
    for k, v in upy.iteritems(d):
        if fn(k, v):
            filtered[k] = v
    return filtered

@ejectable(deps = ["subsets", "sequencify"])
def dict_combinations(struct, must = None):
    struct  = struct.copy()

    keys    = struct.keys()

    if must:
        keys_combinations = [keys]
    else:
        keys_combinations = subsets(keys)

    results = []

    for key_combination in keys_combinations:
        result = {}

        for key in key_combination:
            values = sequencify(struct[key])
            for value in values:
                result[key] = value
                
        results.append(result)

    return results