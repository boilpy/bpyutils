import os.path as osp
from threading import Lock
import json

from upyog.util._dict  import AutoDict, autodict, merge_dict
from upyog.util.system import write, read
from upyog.util.string import strip, safe_decode
from upyog.util.array  import is_list_like
from upyog.util.types  import ordered
from upyog import log
from upyog.util.eject import ejectable
from upyog._compat import Mapping

logger = log.get_logger(__name__)

class JSONEncoder(json.JSONEncoder):
    def default(self, obj):
        try:
            import numpy as np

            if isinstance(obj, np.integer):
                return int(obj)
            elif isinstance(obj, np.floating):
                return float(obj)
            elif isinstance(obj, np.ndarray):
                return obj.tolist()
        except ImportError:
            pass

        return json.JSONEncoder.default(self, obj)

class JSONLogger(AutoDict):
    locks = {
        "io": Lock()
    }

    def __init__(self, path, indent = 2, *args, **kwargs):
        if not len(args):
            args = [ autodict ]

        self._super  = super(JSONLogger, self)
        self._super.__init__(*args, **kwargs)

        self._path   = osp.abspath(path)
        self._indent = indent

        self._store  = self.read()

    @property
    def store(self):
        return getattr(self, "_store", {})

    def _get_content(self):
        path    = self._path
        content = json.loads(strip(read(path)) or r"{}")

        return content

    def read(self):
        path = self._path
        data = self.store

        if not osp.exists(path):
            if data:
                self.save()
        else:
            with self.locks['io']:
                content = self._get_content()
                data    = merge_dict(data, content)

        return autodict(data)

    def __getitem__(self, key):
        value = self._store[key]
        return value

    def __setitem__(self, key, value):
        self._store[key] = value
        self.save()

    def __delitem__(self, key):
        del self._store[key]
        self.save()

    def __iter__(self):
        return iter(self._store)

    def __len__(self):
        return len(self._store)

    def save(self):
        path    = self._path
        indent  = self._indent
        store   = self.store

        with self.locks["io"]:
            if osp.exists(path):
                content = self._get_content()
                store   = merge_dict(content, store, deep = True)

            data = json.dumps(store, indent = indent, cls = JSONEncoder)
                
            write(path, data, force = True)

    def __repr__(self):
        return str(self.store)

@ejectable(deps = ["is_list_like", "safe_decode", "read"])
def load_json(path, *args, **kwargs):
    import json, os.path as osp
    from collections.abc import Mapping

    object_hook = kwargs.pop("object_hook", None)

    if is_list_like(path) or isinstance(path, Mapping):
        return path

    path = safe_decode(path)

    if isinstance(path, str):
        if osp.isfile(path):
            content = read(path, *args, **kwargs)
        else:
            content = path
    else:
        content = read(path, *args, **kwargs)

    data = json.loads(content, object_hook = object_hook)

    return data

@ejectable(deps = ["write"])
def dump_json(data, path = None, *args, **kwargs):
    import json
    force = kwargs.pop("force", False)

    content = json.dumps(data, *args, **kwargs)
    
    if path:
        write(path, content, force = force)

    return content

@ejectable(deps = ["ordered", "load_json"])
def compare_json(a, b):
    a = load_json(a)
    b = load_json(b)
    
    return ordered(a) == ordered(b)
