from __future__ import absolute_import

try:
    import os

    if os.environ.get("upyog_GEVENT_PATCH"):
        from gevent import monkey
        monkey.patch_all(threaded = False, select = False)
except ImportError:
    pass

from pprint import pprint

# imports - module imports
from upyog.__attr__ import (
    __name__,
    __version__,
    __description__,
    __author__
)
from builtins import *
from upyog.util.eject import ejectable
from upyog import cli
from upyog.__main__    import main
from upyog.config      import Settings
from upyog.util.jobs   import run_all as run_all_jobs, run_job
from upyog.api.base    import (
    BaseClient,
    AsyncBaseClient,
    # SuperClient,
    # SuperAsyncClient
)
from upyog.api.response import Response
from upyog.util.cli import (
    get_ansi_code,
    format_ansi
)
from upyog.util._dict  import (
    merge_dict,
    merge_deep,
    dict_from_list,
    autodict,
    lkeys,
    lvalues,
    litems,
    check_dict_struct,
    is_subdict,
    getattr2, hasattr2, setattr2,
    reverse_dict,
    common_dict,
    subtract_dict,
    pretty_dict,
    param_dict,
    pop,
    magic_dict,
    dict_keys,
    dict_values,
    dict_items,
    dict_filter,
    dict_combinations
)
from upyog.util._async import (
    asyncify,
    aenumerate,
    acombine,
    aiterable,
    AsyncIterator,
    run_in_bg
)
from upyog.util._json import (
    load_json,
    dump_json,
    JSONLogger,
    compare_json
)
from upyog._compat import (
    iteritems,
    iterkeys,
    itervalues,
    urlparse,
    quote as urlquote,
    StringIO,
    is_python_version,
    Mapping,
    BytesIO
)
from upyog.util.array  import (
    compact,
    squash,
    flatten,
    sequencify,
    chunkify,
    normalize,
    is_list_like,
    is_ichunk,
    iterify,
    is_subset,
    group_by,
    find,
    chain,
    pluck,
    subsets
)
from upyog.util.string import (
    sanitize_html,
    sanitize,
    lower,
    upper,
    capitalize,
    strip,
    get_random_str,
    pluralize,
    labelize,
    safe_encode,
    safe_decode,
    ellipsis,
    encapsulate,
    to_html,
    is_ascii,
    kebab_case,
    snake_case,
    charsplit,
    strip_ansi,
    sanitize_text,
    format2,
    replace
)
from upyog.util._xml import (
    xml2dict,
    dict2xml
)
from upyog.util._crypto import (
    sha256
)
from upyog.util.datetime import (
    check_datetime_format,
    get_timestamp_str,
    auto_datetime,
    human_datetime,
    now,
    utcnow
)
import upyog.util.datetime as dt
from upyog.util.types    import (
    get_function_arguments,
    auto_typecast,
    build_fn,
    classname,
    lmap,
    array_filter,
    lset,
    is_num_like,
    to_object,
    combinations,
    is_dict_like,
    str2bool,
    gen2seq,
    check_array,
    combinations
)
from upyog.util.system import (
    get_files,
    popen,
    ShellEnvironment,
    make_temp_dir,
    make_temp_file,
    unzip,
    makedirs,
    split_path,
    extract_all,
    check_path,
    abslistdir,
    sha256sum,
    pardir,
    which,
    remove,
    walk,
    read,
    write,
    dict_to_cmd_args,
    copy,
    list_tree,
    list_files,
    make_archive,
    readlines,
    parse_config_string,
    makepath,
    is_tty,
    join2
)
from upyog.util.environ import (
    getenv,
    value_to_envval,
    getenvvar,
    create_param_string
)
from upyog.util._csv import (
    read_csv,
    write as write_csv,
    rows_to_dicts
)
import upyog.util._math as math
from upyog.db import (
    get_connection as get_db_connection,
)
from upyog.util.request import (
    download_file
)
from upyog.util.mixin import (
    create_obj_registerer
)
from upyog.util.imports import (
    get_handler,
    import_handler,
    import_or_raise
)
from upyog.config import (
    get_config_path,
    load_config
)
from upyog.const import (
    CPU_COUNT
)
from upyog.util.progress import (
    progress
)
from upyog.cli.parser import (
    get_base_parser,
    ConfigFileAction
)
from upyog.cli.util import (
    confirm
)
from upyog.exception import (
    PopenError,
    DependencyNotFoundError
)
from upyog.i18n import _
from upyog.model import BaseObject
from upyog.util.log import (
    get_log_level,
    get_logger,
    StepLogger
)
from upyog.log import log_fn
from upyog.limits import (
    MAX_UNSIGNED_SHORT
)
from upyog.util.template import (
    render_template,
    render_jinja_template,
    JINJA_TEMPLATE_EXTENSIONS
)
from upyog.util.error import (
    pretty_print_error
)
from upyog.util.misc import (
    retry
)
from upyog.util.op import Op, O as OpType
from upyog.util.fn import (
    cmp,
    select,
    noop,
    anoop
)
from upyog.util.query import where
from upyog.util.profile import aprofile
from upyog.util.time import (
    timeit,
    atimeit
)
from upyog.cache import Cache
from upyog.util.algo import find_best_groups
from upyog.util._tqdm import FakeAsyncTqdm
from upyog.table import (
    Table,
    render_table
)
from upyog.api.base import (
    AsyncBaseClient,
    SuperClient,
    SuperAsyncClient
)
from upyog.util._aws import (
    is_lambda,
    awsgetenv,
    get_aws_credentials,
    AWS_DEFAULT,
    AWSSigV4Auth,
    AWSClient,
    get_boto3_session,
    get_boto3_client,
    invoke_lambda,
    check_ddb_update,
    get_ddb_table_name,
    get_sfn_executions
)

settings = Settings()

def get_version_str():
    version = "%s%s" % (__version__, " (%s)" % __build__ if __build__ else "")
    return version