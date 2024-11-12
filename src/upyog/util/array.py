# pylint: disable=E1101

# imports - compatibility imports
from upyog._compat    import is_python_version, range
from upyog.util._dict import autodict
from upyog.util.eject import ejectable

# imports - standard imports
import itertools

def compact(arr, type_ = list):
    """
    Creates an array with all falsey values removed. The values False, None, 0, "" are falsey.

    :param arr: The array to be compacted.
    :type arr: list, tuple
    :param type_: The type of sequence to be returned, defaults to list.

    :return: Compacted array.

    Example::

        compact([1, None, 2, False, 3, 4, "", 5])
        [1, 2, 3, 4, 5]
    """
    return type_(filter(bool, arr))

@ejectable(deps = ["is_list_like"])
def squash(seq):
    """
    Return the object in an array in case there is just a single element.

    :param arr: The array to be squashed.

    :return: The squashed array.

    Example::

        squash([1, 2, 3, 4, 5])
        [1, 2, 3, 4, 5]
        squash([1])
        1
    """
    value = seq

    if is_list_like(value) and len(value) == 1:
        value = value[0]
    
    return value

def flatten(arr):
    """
    Flatten an array in case it is multi-dimensional.

    :param arr: The array to be flattened.

    :return: The flattened array.

    Example::

        flatten([[1], [2, 3], [4, 5, 6]])
        [1, 2, 3, 4, 5]
    """
    if is_python_version(major = 2, minor = 6): # pragma: no cover
        chainer = itertools.chain.from_iterable
    else:
        chainer = itertools.chain

    flattened = list(chainer(*arr))

    return flattened

def iterify(value):
    """
    Convert a value into iterable.

    :param arr: The object to be converted to iterable.

    :return: An iterator.

    Example::

        iterify([1])
        [1]
        iterify(3)
        [3]
    """
    if not isinstance(value, (list, tuple)):
        value = list([value])

    value = iter(value)
        
    return value

@ejectable()
def chunkify(arr, n):
    """
    Divide an array into chunks wherein each chunk contains "n" elements.

    :param arr: The array to be chunked.
    :param n: The number of elements in each chunk.

    :return: A generator consisting of arrays containing "n" elements each.

    Example::

        sequencify([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 3)
    """
    arr = list(arr)
    for i in range(0, len(arr), n):
        yield arr[i:i + n]

@ejectable(deps = ["autodict"])
def group_by(data, group):
    from collections import defaultdict
    results = defaultdict(list)

    for d in data:
        key = d.get(group)
        results[key].append(d)

    return results

def find(arr, kind, default = None, raise_err = False):
    obj = kind

    if not callable(kind):
        kind = lambda x: x == obj
    
    found = list(filter(kind, arr))

    if not found:
        if raise_err:
            raise ValueError("%s not found in array." % obj)
        else:
            found = default
    else:
        found = squash(found)

    return found

def clip(arr, low = None, high = None):
    clipped = []

    for value in arr:
        if low is not None and value < low:
            value = low
        elif high is not None and value > high:
            value = high
            
        clipped.append(value)

    return clipped

def normalize(arr, max_ = None, a = 0, b = 1):
    if len(arr) > 0:
        min_ = min(arr)
        max_ = max_ or max(arr)

        for i, value in enumerate(arr):
            if max_ != min_:
                arr[i] = ((value - min_) / (max_ - min_) * (b - a)) + a
            else:
                arr[i] = a

    return arr

l = list

@ejectable()
def is_list_like(obj):
    """
    Check if an object is list-like.

    :param obj: The object to be checked.

    Example::

        is_list_like([1, 2, 3])
        True
        is_list_like(1)
        False
    """
    return isinstance(obj, (list, tuple, set, frozenset))

@ejectable()
def is_sequence_like(obj):
    """
    Check if an object is sequence-like.

    :param obj: The object to be checked.

    Example::

        is_sequence_like([1, 2, 3])
        True
        is_sequence_like(1)
        False
    """
    return is_list_like(obj) or isinstance(obj, str)

@ejectable(deps = is_list_like)
def sequencify(value, type_ = list):
    """
    Convert a value into array-like.

    :param arr: The object to be converted to array-like.

    :return: A sequence.

    Example::

        sequencify([1])
        [1]
        sequencify(3)
        [3]
    """
    if not is_list_like(value):
        value = list([value])

    value = type_(value)
        
    return value

@ejectable()
def is_ichunk(i, chunk_size):
    return i > 0 and i % chunk_size == 0

@ejectable()
def is_subset(a, b):
    return set(a) <= set(b)

@ejectable()
def chain(*fns, query):
    result = query
    for fn in fns:
        result = fn(result)
    return result

@ejectable()
def pluck(arr, key):
    return [d[key] for d in arr]