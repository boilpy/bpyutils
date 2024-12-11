# imports - compatibility imports
from __future__ import absolute_import

# imports - standard imports
import os.path as osp
import multiprocessing as mp
from threading import Lock
import platform
from collections import namedtuple

# imports - module imports
from upyog              import __name__ as NAME, __version__
from upyog.util.system  import pardir, makedirs, get_user
from upyog.util.environ import getenv
from upyog.util.types   import auto_typecast
from upyog.util._dict   import autodict
from upyog.util._json   import load_json
from upyog._compat      import (iterkeys, itervalues, iteritems, configparser as cp)
from upyog.log import get_logger
from upyog.util.eject   import ejectable
from upyog.util.system  import make_temp_file

logger = get_logger(__name__)

@ejectable(deps = ["getenv"])
def get_config_path(name):
    import os.path as osp

    if getenv("LAMBDA_FUNCTION_NAME", prefix = "AWS"):
        basedir = "/tmp"
    else:
        basedir = osp.expanduser("~")

    return osp.join(basedir, ".config", name)

PATH                = autodict()
PATH["ROOT"]        = pardir(__file__, 3)
PATH["BASE"]        = osp.join(PATH["ROOT"], "src", NAME)
PATH["DATA"]        = osp.join(PATH["BASE"], "data")
PATH["CACHE"]       = get_config_path(NAME)
PATH["JOBS"]        = osp.join(PATH["BASE"], "jobs")
PATH["TEMPLATES"]   = osp.join(PATH["DATA"], "templates")
PATH["TESTS"]       = osp.join(PATH["ROOT"], "tests", NAME)

class Configuration(object):
    # BUGFIX: # 63 Always complains about invalid config.ini - https://github.com/achillesrasquinha/pipupgrade/issues/63
    #         Use threading.Lock() around disk IO
    locks = { "readwrite": Lock() }

    def __init__(self, location = PATH["CACHE"], name = "config"):
        config = getenv("CONFIG")

        if getenv("LAMBDA_FUNCTION_NAME", prefix = "AWS"):
            location = "/tmp"

        if not config:
            self.name     = "%s.ini" % name
            self.location = location
            makedirs(self.location, exist_ok = True)
        else:
            self.name     = osp.basename(config)
            self.location = osp.dirname(config)
            
        self.config = self.read()

    @classmethod
    def __del__(self):
        # Clean up leaked semaphores Lock() before thread exit
        # This function gets called atexit once per SpawnPoolWorker-1 thread
        for key in list(self.locks.keys()):
            self.locks[key].acquire()
            self.locks[key].release()
            del self.locks[key]

    def read(self):
        with self.locks['readwrite']:
            path        = osp.join(self.location, self.name)
            self.config = cp.ConfigParser()
            if osp.exists(path):
                self.config.read(path)
        return self.config

    def write(self):
        with self.locks['readwrite']:
            path = osp.join(self.location, self.name)
            with open(path, "w") as f:
                self.config.write(f)

    def get(self, section, key, default = None, raise_err = True, auto_type = True):
        config = self.config

        if not config.has_section(section):
            raise KeyError("No section %s found." % section)
        
        value = default

        if not config.has_option(section, key):
            if raise_err:
                raise KeyError("No key %s found." % key)
        else:
            value = config.get(section, key)

        if auto_type:
            value = auto_typecast(value)

        return value

    def set(self, section, key, value, force = False):
        config = self.config
        value  = str(value)

        if not config.has_section(section):
            config.add_section(section)

        if force or not config.has_option(section, key):
            config.set(section, key, value)
            self.write()

class Settings(object):
    _DEFAULTS = {
              "version": __version__,
        "cache_timeout": 60 * 60 * 24, # 1 day
                 "jobs": mp.cpu_count(),
        "max_chunk_download_bytes": 1024
    }

    def __init__(self, location = PATH["CACHE"], defaults = None):
        self.config = Configuration(location = location)

        self._init(defaults = defaults)

    def _init(self, defaults = None):
        for k, v in iteritems(defaults or Settings._DEFAULTS):
            self.set(k, v)

    def get(self, key, default = None, raise_err = True, auto_type = True):
        return self.config.get("settings", key, default = default, raise_err = raise_err, auto_type = auto_type)

    def set(self, key, value):
        self.config.set("settings", key, value)

    def to_dict(self):
        parser      = self.config.config
        sections    = parser._sections

        sections    = load_json(sections)

        return sections 

def environment():
    environ = dict()
    
    environ["version"]          = __version__
    environ["python_version"]   = platform.python_version()
    environ["os"]               = platform.platform()
    environ["config"]           = dict(
        path = dict(PATH)
    )
    environ["user"]             = get_user()

    from upyog import settings
    environ["settings"]         = settings.to_dict()

    return environ

@ejectable(deps = ["load_json"])
def load_config(fpath, raw = False):
    import os.path as osp

    data  = None

    with make_temp_file() as tmp_file:
        if not raw:
            fpath = osp.abspath(fpath)
            f_handler = open(fpath, "r")
        else:
            with open(tmp_file, "w") as f:
                f.write(fpath)
                
            f_handler = open(tmp_file, "r")

        try:
            try:
                import yaml

                try:
                    from yamlinclude import YamlIncludeConstructor

                    basedir = osp.dirname(fpath)
                    
                    YamlIncludeConstructor.add_to_loader_class(
                        loader_class=yaml.Loader,
                        base_dir=basedir
                    )
                except ImportError:
                    pass

                data = yaml.safe_load(f_handler)
            except ImportError:
                data = load_json(f_handler)
        except ImportError:
            data = load_json(f_handler)
        finally:
            f_handler.close()

    return data