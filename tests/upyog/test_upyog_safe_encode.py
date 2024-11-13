def test_upyog_safe_encode():
    import pytest
    import upyog as upy

    assert upy.safe_encode(b'hello') == b'hello'
    assert upy.safe_encode('hello')  == b'hello'
    assert upy.safe_encode(u'hello') == b'hello'