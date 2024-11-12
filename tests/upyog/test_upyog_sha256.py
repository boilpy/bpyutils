def test_upyog_sha256():
    import pytest
    import upyog as upy
    
    assert upy.sha256('foobar')[:8]  == 'c3ab8ff1'
    assert upy.sha256(b'foobar')[:8] == 'c3ab8ff1'

    with pytest.raises(TypeError):
        upy.sha256(1)