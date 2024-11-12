def test_upyog_capitalize():
    import upyog as upy

    assert upy.capitalize("hello")        == "Hello"
    assert upy.capitalize("hello world")  == "Hello world"
    assert upy.capitalize("hello world!") == "Hello world!"
    assert upy.capitalize("HELLO")        == "Hello"
    assert upy.capitalize("hElLo")        == "Hello"