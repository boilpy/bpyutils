from collections import defaultdict

from upyog._compat import iteritems, Mapping, iterkeys, itervalues

def merge_deep(source, dest):
    # https://stackoverflow.com/a/20666342
    for key, value in iteritems(source):
        if isinstance(value, dict):
            node = dest.setdefault(key, {})
            merge_deep(value, node)
        else:
            dest[key] = value
            
    return dest

def merge_dict(*args, **kwargs):
    """
    Merge Dictionaries.
    
    :param args: arguments of dictionaries to be merged. `merge_dict` will override keys from right to left.

    :returns: dict

    Example::
    
        >>> bpy.merge_dict({ 'foo': 'bar' }, { 'bar': 'baz' }, { 'baz': 'boo' })
        {'foo': 'bar', 'bar': 'baz', 'baz': 'boo'}
        >>> bpy.merge_dict({ 'foo': 'bar' }, { 'foo': 'baz', 'bar': 'boo' })
        {'foo': 'baz', 'bar': 'boo'}
    """
    deep = kwargs.get("deep", False)

    merged = dict()

    for arg in args:
        copy = arg.copy()

        if deep:
            merged = merge_deep(copy, merged)
        else:
            merged.update(copy)

    return merged

def dict_from_list(keys, values = None):
    """
    Generate a dictionary from a list of keys and values.

    :param keys: A list of keys.
    :param values: A list of values.

    :returns: dict

    Example::

        >>> bpy.dict_from_list(['a', 'b', 'c'], [1, 2, 3])
        {'a': 1, 'b': 2, 'c': 3}
    """
    if not values:
        values = [None] * len(keys)

    return dict(zip(keys, values))

class AutoDict(defaultdict):
    __repr__ = dict.__repr__

def autodict(*args, **kwargs):
    """
    Automatically adds a key to a dictionary.

    Example::

        >>> d = bpy.autodict()
        >>> d['foo']['bar']['baz'] = 'boo'
        {'foo': {'bar': {'baz': 'boo'}}}
    """
    _autodict = AutoDict(autodict)
    update    = dict(*args, **kwargs)

    for key, value in iteritems(update):
        if isinstance(value, Mapping):
            value = autodict(value)
        
        _autodict.update({
            key: value
        })
    
    return _autodict

def lkeys(d):
    """
    Get the keys of a dictionary as a list.

    :param d: A dictionary.

    :returns: list

    Example::

        >>> bpy.lkeys({ 'foo': 'bar', 'baz': 'boo' })
        ['foo', 'baz']
    """
    return list(iterkeys(d))

def lvalues(d):
    """
    Get the values of a dictionary as a list.

    :param d: A dictionary.

    :returns: list

    Example::

        >>> bpy.lvalues({ 'foo': 'bar', 'baz': 'boo' })
        ['bar', 'boo']
    """
    return list(itervalues(d))