from upyog.util.string import safe_decode

def b64decode(data):
    import base64
    return safe_decode(base64.b64decode(data))

def b64str(data):
    import base64
    return safe_decode(base64.b64encode(data))