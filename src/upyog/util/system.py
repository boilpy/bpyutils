from __future__ import absolute_import

# imports - compatibility imports
from upyog._compat import iteritems
import upyog as upy

# imports - standard imports
import hashlib
import sys, os, os.path as osp
import errno
import zipfile
import subprocess  as sp
import shutil
import tempfile
import contextlib
from   glob import glob
import fnmatch
import re
import time
import tarfile

# imports - module imports
from upyog.util._dict      import merge_dict
from upyog.exception       import PopenError
from upyog.util.string     import (
    strip,
    safe_decode,
    get_random_str,
    safe_encode
)
from upyog.util.types      import lmap, array_filter, auto_typecast
from upyog.util.array      import sequencify, squash, is_list_like
from upyog.util.environ    import SECRETS, value_to_envval
from upyog._compat         import iteritems, PY2
from upyog.log             import get_logger
from upyog.util.eject import ejectable

LOG = get_logger()

__STDOUT__ = None

VIDEO_EXTENSIONS = (
    ".avi", ".mp4", ".mkv", ".mov", ".flv", ".wmv", ".webm", ".mpg", ".mpeg"
)

@ejectable(deps = ["strip"])
def read(fname, mode = "r", encoding = "utf-8", clean = True):
    """Read content from a given file.

    Args:
        fname (str, Path): The path to the file.
        mode (str): File mode while opening. Defaults to "r".

    Returns:
        [type]: The content within the file.

    Example

        read("path/to/file")
        'Hello, World!'
    """
    if hasattr(fname, "read"):
        data = fname.read()
    else:
        with open(fname, mode = mode or "r", encoding = encoding) as f:
            data = f.read()

            if data and clean:
                data = strip(data)

    return data

@ejectable()
def readlines(*args, **kwargs):
    content = read(*args, **kwargs)
    return content.split("\n")

@ejectable(deps = ["makepath"])
def write(fname, data = None, force = False, append = False, mode = None):
    import os.path as osp

    if not osp.exists(fname) or append or force:
        if force:
            makepath(fname)

        with open(fname, mode = mode or ("a" if append else "w")) as f:
            if data:
                f.write(data)

# NOTE: This is just a copy of the distutils.spawn.find_executable (since distutils is deprecated).
def _find_executable(executable, path=None):
    """Tries to find 'executable' in the directories listed in 'path'.

    A string listing directories separated by 'os.pathsep'; defaults to
    os.environ['PATH'].  Returns the complete filename or None if not found.
    """
    _, ext = os.path.splitext(executable)
    if (sys.platform == 'win32') and (ext != '.exe'):
        executable = executable + '.exe'

    if os.path.isfile(executable):
        return executable

    if path is None:
        path = os.environ.get('PATH', None)
        if path is None:
            try:
                path = os.confstr("CS_PATH")
            except (AttributeError, ValueError):
                # os.confstr() or CS_PATH is not available
                path = os.defpath
        # bpo-35755: Don't use os.defpath if the PATH environment variable is
        # set to an empty string

    # PATH='' doesn't match, whereas PATH=':' looks in the current directory
    if not path:
        return None

    paths = path.split(os.pathsep)
    for p in paths:
        f = os.path.join(p, executable)
        if os.path.isfile(f):
            # the file exists, we have a shot at spawn working
            return f
    return None

def which(executable, raise_err = False):
    exec_ = None

    if not PY2:
        try:
            exec_ = shutil.which(executable)
        except shutil.Error: # pragma: no cover
            pass

    if not exec_:
        # worst to worst case.
        # from distutils.spawn import find_executable
        exec_ = _find_executable(executable)
        
    if not exec_ and raise_err:
        raise ValueError("Executable %s not found." % executable)
    
    return exec_

@ejectable(deps = ["lmap", "array_filter"])
def walk(top, *args, **kwargs):
    import os, os.path as osp, fnmatch, re

    abspath = kwargs.pop("abspath", False)

    if abspath:
        top = osp.abspath(top)

    include = sequencify(kwargs.pop("include", []))
    if include:
        include = 'r|'.join(lmap(fnmatch.translate, include))

    for root, dirs, files in os.walk(top, *args, **kwargs):
        if abspath:
            dirs  = lmap(lambda d: osp.join(root, d), dirs)
            files = lmap(lambda f: osp.join(root, f), files)

        if include:
            files = array_filter(lambda f: re.match(include, f), files)

        yield root, dirs, files

@ejectable()
def pardir(fname, level = 1, raise_err = True):
    """
        Get the parent directory of a given file.

        Args:
            fname (str): The path to the file.
            level (int): The number of levels to go up from the file.
            raise_err (bool): Raise `FileNotFoundError` if a give file isn't found, else ignore.

        Returns:
            str: The parent directory of the file.

        Example:
            >>> pardir("path/to/file")
            '/abspath/path/to'
            >>> pardir("path/to/file", level = 2)
            '/abspath/path'
    """
    import os.path as osp
    
    fname = osp.abspath(fname)

    if not osp.exists(fname) and raise_err:
        raise FileNotFoundError("File %s not found." % fname)

    for _ in range(level):
        prev  = fname
        fname = osp.dirname(fname)
        
        if fname == prev and raise_err:
            raise ValueError("Level is too high.")
    
    return fname

def dict_to_cmd_args(dictionary, prefix = "--", sep = "=", join = " "):
    return join.join([prefix + key + sep + value_to_envval(value) for key, value in iteritems(dictionary)])

@ejectable()
def popen(*args, **kwargs):
    import os, subprocess as sp

    output      = kwargs.get("output", False)
    quiet       = kwargs.get("quiet" , False)
    directory   = kwargs.get("cwd")
    environment = kwargs.get("env")
    shell       = kwargs.get("shell", True)
    raise_err   = kwargs.get("raise_err", True)
    executable  = kwargs.get("executable")

    environ     = os.environ.copy()
    if environment:
        environ.update(environment)

    for k, v in iteritems(environ):
        environ[k] = str(v)

    command     = " ".join([str(arg) for arg in args])

    if not quiet:
        LOG.info("Executing command: %s" % command)

    if quiet:
        output = True
    
    proc        = sp.Popen(command,
        bufsize = -1,
        stdin   = sp.PIPE if output else kwargs.get("stdin"),
        stdout  = sp.PIPE if output else None,
        stderr  = sp.PIPE if output else None,
        env     = environ,
        cwd     = directory,
        shell   = shell,
        executable = executable
    )

    code       = proc.wait()

    if code and raise_err:
        raise PopenError(code, command)

    if output:
        output, error = proc.communicate()

        if output:
            output = safe_decode(output)
            output = strip(output)

        if error:
            error  = safe_decode(error)
            error  = strip(error)

            if not quiet:
                LOG.error("Error executing command %s: %s" % (command, error))

        if quiet:
            return code
        else:
            return code, output, error
    else:
        return code

@ejectable()
def makedirs(dirs, exist_ok = False):
    import os, os.path as osp, errno

    dirs = osp.abspath(dirs)

    try:
        os.makedirs(dirs)
    except OSError as e:
        if not exist_ok or e.errno != errno.EEXIST:
            raise

    return dirs

@ejectable(deps = ["makedirs"])
def makepath(path):
    import os.path as osp

    dirs = osp.dirname(path)
    makedirs(dirs, exist_ok = True)

    write(path)

def touch(filename):
    if not osp.exists(filename):
        with open(filename, "w") as f:
            pass

@ejectable()
def remove(*paths, **kwargs):
    import shutil, os, os.path as osp

    recursive = kwargs.get("recursive", False)
    raise_err = kwargs.get("raise_err", True)

    for path in paths:
        path = osp.realpath(path)

        if osp.isdir(path):
            if recursive:
                shutil.rmtree(path)
            else:
                if raise_err:
                    raise OSError("{path} is a directory.".format(
                        path = path
                    ))
        else:
            try:
                os.remove(path)
            except (OSError, PermissionError):
                if raise_err:
                    raise

ejectable(imports = "contextlib")

@contextlib.contextmanager
def make_temp_dir(root_dir = None, remove = True):
    import shutil, tempfile

    if root_dir:
        makedirs(root_dir, exist_ok = True)
        
    dir_path = tempfile.mkdtemp(dir = root_dir)

    try:
        yield dir_path
    finally:
        if not root_dir and remove:
            shutil.rmtree(dir_path)

@contextlib.contextmanager
def make_temp_file(fname = None):
    with make_temp_dir() as tmp_dir:
        if not fname:
            fname = get_random_str()

        tmp_file = osp.join(tmp_dir, fname)

        touch(tmp_file)
        
        yield tmp_file

def check_gzip(f, raise_err = True):
    """
    Check if a given file is a gzipped file.
    """
    if osp.exists(f):
        with open(f, "rb") as f:
            content = f.read(2)
            
            if content == b"\x1f\x8b":
                return True
            else:
                if raise_err:
                    raise ValueError("File %s is not a gzip file." % f)

    return False

class BaseShell:
    def __init__(self, *args, **kwargs):
        self._kwargs = kwargs

    def __call__(self, *args, **kwargs):
        kwargs = merge_dict(self._kwargs, kwargs)
        return popen(*args, **kwargs)

if PY2:
    def ShellEnvironment(**kwargs):
        yield BaseShell(**kwargs)
else:
    class ShellEnvironment(BaseShell, contextlib.ContextDecorator):
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

def get_os():
    platform = sys.platform
    
    if platform.startswith("linux"):
        return "linux"
    elif platform == "darwin":
        return "macos"
    elif platform == "win32":
        return "windows"

def unzip(path, target = None):
    target = target or osp.dirname(path)
    makedirs(target, exist_ok = True)

    with zipfile.ZipFile(path, "r") as zf:
        zf.extractall(target)

def get_files(dir_, type_ = "*.*"):
    dir_ = osp.abspath(dir_)
    return glob("%s/**/%s" % (dir_, type_), recursive = True)

def get_basename(path):
    return osp.basename(osp.normpath(path))

def make_archive(base_name, *args, **kwargs):
    with make_temp_dir() as tmp_dir:
        source_archive = osp.join(tmp_dir, "archive")
        target_archive = shutil.make_archive(source_archive, *args, **kwargs)

        makepath(base_name)
        shutil.move(target_archive, base_name)

def move(*files, **kwargs):
    """Move a file or a list of files to destination

    Args:
        files (str, `Path`): The source file to move. (Can be a file or a directory).
        dest (str, `Path`): The destination path to move files to (Can be a file or a directory).

    Example:

        move("path/to/file1", "path/to/file2", dest = "path/to/dest")
    """
    dest = kwargs["dest"]

    for f in files:
        shutil.move(f, dest)

def copy(*files, **kwargs):
    """Copy a file or a list of files to destination

    Args:
        files (str, `Path`): The source file to copy. (Can be a file or a directory).
        dest (str, `Path`): The destination path to copy files to (Can be a file or a directory).
        raise_err (bool): Raise `FileNotFoundError` if a give file isn't found, else ignore.

    Raises:
        FileNotFoundError: If a given file isn't found and `raise_err` is not flagged.

    Example:

        copy("path/to/file1", "path/to/file2", dest = "path/to/dest")
    """
    dest  = kwargs["dest"]
    raise_err = kwargs.get("raise_err", False)
    force = kwargs.get("force", False)
    
    for f in files:
        abspath = osp.abspath(f)

        if not osp.exists(abspath) and raise_err:
            raise FileNotFoundError("No file %s found." % abspath)
        else:
            if osp.isdir(abspath):
                if osp.exists(dest):
                    if force:
                        shutil.rmtree(dest)
                    else:
                        raise FileExistsError("Directory %s already exists." % dest)

                shutil.copytree(abspath, dest)
            else:
                if force:
                    makepath(dest)

                shutil.copy2(abspath, dest)

def extract_all(source, dest):
    """Unpack an archive to a desired destination.

    Args:
        source (str, Path): The source path to the archive file.
        dest (str, Path): The destination path to extract the archive to.

    Example

        extract_all("path/to/src", "path/to/dest")
    """
    source = osp.abspath(source)
    dest   = osp.abspath(dest)

    if source.endswith(".bz2"):
        with tarfile.open(source, "r:bz2") as tar:
            tar.extractall(dest)
    else:
        shutil.unpack_archive(source, dest)

@ejectable()
def check_path(path, raise_err = True):
    import os.path as osp

    path = osp.abspath(path)

    if not osp.exists(path) and raise_err:
        raise FileNotFoundError("Path %s not found." % path)

    return path

def check_dir(path, raise_err = True):
    path = check_path(path, raise_err = raise_err)

    if not osp.isdir(path) and raise_err:
        raise NotADirectoryError("Path %s is not a directory." % path)

    return path

@ejectable(deps = ["check_path"])
def check_file(path, raise_err = True):
    import os.path as osp

    path = check_path(path, raise_err = raise_err)

    if not osp.isfile(path) and raise_err:
        raise FileNotFoundError("Path %s is not a file." % path)

    return path

def list_tree(*args, **kwargs):
    return list(walk(*args, **kwargs))

@ejectable(deps = [walk])
def list_files(*args, **kwargs):
    include_dirs = kwargs.pop("include_dirs", True)
    files = []

    for root, dirs, fs in walk(*args, **kwargs):
        if include_dirs:
            for dir_ in dirs:
                files.append(osp.join(root, dir_))

        for f in fs:
            files.append(osp.join(root, f))

    return files

def abslistdir(path, filter_ = None):
    path = check_path(path)
    l = lmap(lambda f: osp.join(path, f), os.listdir(path))
    
    if filter_:
        l = array_filter(filter_, l)

    return l

def is_video(path):
    return osp.splitext(path)[1] in VIDEO_EXTENSIONS

def split_path(path):
    head, tail = osp.split(path)
    tail, extension = osp.splitext(tail)
    return head, tail, extension

def wc(path):
    from pathlib import Path
    
    p = Path(path)
    stat = p.stat()

    return stat.st_size

def timeit(func):
    def wrapper(*args, **kwargs):
        start   = time.time()
        result  = func(*args, **kwargs)
        end     = time.time()

        duration = end - start
        
        return duration, result

    return wrapper

def make_exec(path):
    st = os.stat(path)
    
    mode = st.st_mode
    mode |= (mode & 0o444) >> 2

    os.chmod(path, mode)

def sha256sum(fpath):
    data   = safe_encode(read(fpath, encoding = "utf-8"))
    digest = hashlib.sha256(data)
    hash_  = digest.hexdigest()

    return hash_

def get_user():
    username = os.environ.get("USER")
    return username

@ejectable(deps = ["strip", "lmap", "squash", "auto_typecast", "is_list_like"])
def parse_config_string(config, auto_cast = True):
    params = config.split(";")
    result = {}

    for param in params:
        key, value = param.split("=")
        key   = strip(key)

        value = strip(value)
        value = lmap(strip, value.split(","))
        value = squash(value)

        if auto_cast:
            if is_list_like(value):
                value = lmap(auto_typecast, value)
            else:
                value = auto_typecast(value)
                
        result[key] = value
    
    return result

@ejectable()
def is_tty():
    import sys

    return sys.stdout.isatty()

@ejectable()
def join2(*args, **kwargs):
    output = ""
    path   = kwargs.pop("path", False)

    if path:
        import os.path as osp
        for arg in args:
            output = osp.join(output, arg)
    else:
        output = "".join(args)

    return output