class FakeAsyncTqdm:
    def __init__(self, iterable, *args, **kwargs):
        self.iterable = iterable

    def __len__(self):
        return len(self.iterable)

    def __enter__(self):
        return self

    def __exit__(self, *args, **kwargs):
        pass

    async def __aiter__(self):
        return self.iterable.__iter__()

    def update(self, *args, **kwargs):
        pass

    def close(self):
        pass

    def __aiter__(self):
        return self.iterable.__aiter__()
    
    def __anext__(self):
        return self.iterable.__anext__()
    
def progress(*args, **kwargs):
    try:
        from tqdm import tqdm as _tqdm
        return _tqdm(*args, **kwargs)
    except ImportError:
        return iter(FakeAsyncTqdm(*args, **kwargs))