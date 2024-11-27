def test_upyog_get_boto3_session():
    import upyog as upy
    
    session_1 = upy.get_boto3_session()
    assert session_1 is not None
    assert session_1.region_name == upy.AWS_DEFAULT["region"]

    region_name = "us-east-1"

    session_2 = upy.get_boto3_session(region_name=region_name)
    assert session_2 is not None
    assert session_2.region_name == region_name

    assert id(session_1) != id(session_2)

    session_3 = upy.get_boto3_session(region_name=region_name)
    assert session_3 is not None

    assert id(session_2) == id(session_3)