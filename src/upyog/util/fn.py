import upyog as upy

def pop(x, *keys):
    x = x.copy()

    values = []

    for key in keys:
        values.append(x[key])
        del x[key]

    return x, upy.squash(values)

def cmp(a, b):
    if a < b:
        return -1
    elif a > b:
        return 1
    else:
        return 0

def select(x, *keys):
    x = x.copy()
    y = {}

    for key in keys:
        y[key] = x[key]

    return y
