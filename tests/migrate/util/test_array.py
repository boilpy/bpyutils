# imports - module imports
from upyog.util.array import (
    compact,
    squash,
    flatten
)

# imports - test imports
import pytest

def test_compat():
    assert compact([1, 2, None])                        == [1, 2]
    assert compact([1, 2])                              == [1, 2]
    assert compact([1, 2, "", "foo"])                   == [1, 2, "foo"]
    assert compact(["foo", "bar", ""], type_ = tuple)   == ("foo", "bar")

def test_flatten():
    assert flatten([[1, 2], [3, 4]])    == [1, 2, 3, 4]
    assert flatten([[1, 2]])            == [1, 2]
    assert flatten([[1, 2], [ ]])       == [1, 2]

    with pytest.raises(TypeError):
        assert flatten([[1, 2], None])

from upyog.util.array import (
  chunkify,
  group_by,
  find,
  clip
)

def test_compact():
    raise NotImplementedError

def test_chunkify():
    raise NotImplementedError

def test_group_by():
    raise NotImplementedError

def test_find():
    raise NotImplementedError

def test_clip():
    assert clip([1, 2, 3, 4, 5], low = 2, high = 4) == [2, 2, 3, 4, 4]
    assert clip([1, 2, 3, 4, 5], low = 2) == [2, 2, 3, 4, 5]