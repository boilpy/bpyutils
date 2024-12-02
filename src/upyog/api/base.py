# imports - standard imports
import os, random, os.path as osp
import re
import string
import json, time, asyncio

from upyog.util._dict           import autodict, dict_items, check_dict_struct
from upyog.model.base           import BaseObject
from upyog.util.imports         import import_or_raise
from upyog._compat              import (
    urlencode, iteritems, urlparse,
    Mapping
)
from upyog.util.array           import (
    sequencify,
    squash
)
from upyog.log                  import get_logger
from upyog.util.request         import (
    download_file
)
from upyog.util.string          import lower, upper
from upyog.util.eject           import ejectable
from upyog.util._dict           import check_dict_struct, setattr2
from upyog.util.environ         import getenv

logger = get_logger()

def _path_to_method_name(path):
    # strip leading and trailing "/"
    formatted = path.strip("/")
    # replace all "/" with "_"
    formatted = formatted.replace("/", "_")
    # insert "_" before every capital letter.
    formatted = re.sub(r"(\w)([A-Z])", r"\1_\2", formatted)
    # convert to lowercase
    formatted = formatted.lower()

    method_name = formatted

    return method_name

@ejectable(deps = ["BaseObject"])
class BaseClient(BaseObject):
    _REPR_ATTRS = ("url",)

    """
    :param url: A base URL to use.
    :param proxies: A dictionary/list of proxies to use. If a list is passed,
        each element in the list should be a dictionary of the format 
        ``{ protocol: ip }``.
    :param test: Attempt to test the connection to the base url.
    """
    def __init__(self, url = None, proxies = [ ], test = False, token = None,
                 verbose = False, rate = None, auth = None, session = None, async_ = False,
                 retries = 1, on_error = None, timeout = None, api_key = None, 
                 cert = None, **kwargs):
        super_ = super(BaseClient, self)
        super_.__init__(**kwargs)

        self._url = self._format_uri_path(url or getattr(self, "url") or "",
            **kwargs)
        
        self._async   = async_

        if self._async:
            self._session = None
        else:
            self._requests = import_or_raise("requests")
            self._session  = session or self._requests.Session()

        if proxies and \
            not isinstance(proxies, (Mapping, list, tuple)):
            raise TypeError((
                "proxies %s are not of valid type. You must "
                "either a dictionary of a list of dictionaries of the "
                "following format { protocol: ip }."))

        if isinstance(proxies, Mapping):
            proxies = [proxies]

        self.token = token

        self._auth  = auth

        self._proxies = proxies
        self._rate    = rate

        self._retries  = retries
        self._timeout  = timeout

        self._api_key  = api_key
        self._cert     = cert

        self._build_api()

        if test:
            self.ping()

    def _format_uri_path(self, url, **kwargs):
        formatter = string.Formatter()
        str_args  = formatter.parse(url)
        uri_keys  = [arg[1] for arg in str_args if arg[1]]

        variables = getattr(self, "variables", {})
        variables.update(kwargs.get("variables", {}))

        to_format = { }

        for key in uri_keys:
            key_config = variables.get(key, None)
            if not key_config:
                if not key in kwargs:
                    raise ValueError("Missing argument '%s' for URL." % key)
                else:
                    to_format[key] = kwargs[key]
            else:
                required = key_config.get("required", False)
                default  = key_config.get("default", None)

                if required and not key in kwargs:
                        raise ValueError("Missing argument '%s' for URL." % key)
                else:
                    to_format[key] = kwargs.get(key, default)

        formatted = url.format(**to_format)

        return formatted

    @property
    def auth(self):
        auth = getattr(self, "_auth", None)
        return auth

    @auth.setter
    def auth(self, value):
        self._auth = value

    @property
    def url(self):
        url = getattr(self, "_url", None)
        
        if url:
            return self._format_uri_path(url)

    def _create_api_function(self, api, base_config = {}):
        METHOD_CALLERS = {
               "GET": self.get,
              "POST": self.post,
               "PUT": self.put,
             "PATCH": self.patch,
            "DELETE": self.delete,
              "AGET": self.aget,
             "APOST": self.apost,
              "APUT": self.aput,
           "ADELETE": self.adelete,
            "APATCH": self.apatch,
        }

        doc = api.get("doc")

        def fn(*args, **kwargs):
            data = {}

            query = self._format_uri_path(api["path"], variables = api.get("variables", {}), **kwargs)

            params = api.get("params")
            method = api.get("method", "GET")
            auth_required = api.get("auth", False)
            stream = api.get("stream", False)
            blob = api.get("blob", False)

            if params:
                parameters = []

                if isinstance(params, Mapping):
                    for param, info in iteritems(params):
                        type_    = info.get("type", "param")
                        required = info.get("required")
                        argument = info.get("argument", param)
                        default  = info.get("default")

                        if (type_ == "path" or required) and argument not in kwargs:
                            raise ValueError("Argument %s is not passed." % argument)

                        if type_ == "path":
                            value = kwargs.get(argument)
                            query = query.replace(":%s" % param, str(value))
                        else:
                            if callable(default):
                                default = default(*args, **kwargs)

                            kwargs[param] = kwargs.get(argument, default)
                            parameters.append(param)

                parameters = sequencify(parameters)
                for parameter in parameters:
                    if parameter in kwargs:
                        value = kwargs.get(parameter)
                        data[parameter] = value

            if method == "POST":
                if "json" in kwargs:
                    args = {
                        "data": json.dumps(kwargs["json"]),
                        "headers": {"Content-Type": "application/json"}
                    }
                elif blob:
                    args = {"files": data}
                else:
                    args = {"data": data}
            else:
                args = {"params": data}

            if auth_required:
                if self.auth:
                    args.update({"auth": self.auth})

            after_request = None

            if stream:
                args.update({"stream": True})
                target = kwargs.get("target", None)
                if target:
                    after_request = lambda response, **kwargs: download_file(response, target)

            method_caller = METHOD_CALLERS.get(method, self.get)

            if "mock_response" in api:
                response = api["mock_response"](query, **args)
            else:
                response = method_caller(query, **args)

            after_request = api.get("after_request", base_config.get("after_request", None)) \
                or after_request

            if after_request:
                response = after_request(response, req_args = args)
            
            return response

        if doc:
            fn.__doc__ = doc

        return fn
        
    def _build_api(self):
        api_config = getattr(self, "api", {})
        if api_config:
            if "paths" in api_config:
                for api in api_config["paths"]:
                    if isinstance(api, str):
                        api = dict(path = api)
                    elif isinstance(api, (list, tuple)):
                        api = dict(path = api[0], method_name = api[1])

                    query = api["path"]

                    fn = self._create_api_function(api, base_config = api_config)

                    method_name = api.get("method_name", _path_to_method_name(query))

                    setattr(self, method_name, fn)

    def _build_url(self, *args, **kwargs):
        params  = kwargs.pop("params", None) 
        prefix  = kwargs.get("prefix", True)
        
        parts   = []

        if prefix:
            parts.append(self._url)

        url = "/".join(map(str, sequencify(parts) + sequencify(args)))

        if params:
            encoded  = urlencode(params)
            url     += "?%s" % encoded

        api = kwargs.get("api", {})
        url = self._format_uri_path(url, variables = api.get("variables", {}), **kwargs)

        return url

    def request(self, method, path = None, *args, **kwargs):
        req_args = self._get_req_args(method, path, *args, **kwargs)
        self._session.verify = req_args["verify"]

        if self._api_key:
            headers = req_args["headers"]
            headers.update({"X-Api-Key": self._api_key})

        cert = self._cert or req_args["kwargs"].pop("cert", None)

        response = self._session.request(method, req_args["url"],
            cert = cert,
            headers = req_args["headers"],
            *req_args["args"],
            **req_args["kwargs"]
        )

        return response # TODO: ?

    def _get_req_args(self, method, path = None, *args, **kwargs):
        raise_error = kwargs.pop("raise_error", True)
        token       = kwargs.pop("token",       self.token)

        headers     = getattr(self, "headers", {})
        headers.update(kwargs.pop("headers", {}))

        proxies     = kwargs.pop("proxies", self._proxies)
        data        = kwargs.get("params",  kwargs.get("data"))
        prefix      = kwargs.pop("prefix",  True)
        async_      = kwargs.pop("async_",  False)
        wait        = kwargs.pop("wait",    None)

        verify      = kwargs.pop("verify", False)

        if token:
            headers.update({
                "Authorization": "Bearer %s" % token,
            })

        if self._auth:
            kwargs.update({"auth": self._auth})

        if proxies:
            proxies = random.choice(proxies)

        url = self._build_url(path, prefix = prefix)

        parsed = urlparse(url)
        logger.info("%s %s %s" % (parsed.netloc, method, parsed.path))

        return {
            "url": url,
            "headers": headers,
            "proxies": proxies,
            "data": data,
            "prefix": prefix,
            "async_": async_,
            "raise_error": raise_error,
            "verify": verify,
            "args": args,
            "kwargs": kwargs,
            "wait": wait
        }

    async def arequest(self, method, path = None, *args, **kwargs):
        req_args = self._get_req_args(method, path, *args, **kwargs)

        async with self:
            verify = req_args.pop("verify", None)
            httpx  = import_or_raise("httpx")
            
            port  = req_args["kwargs"].pop("port", None)
            url   = req_args["url"]
            if port:
                url_parsed = urlparse(req_args["url"])
                url = "%s://%s:%s%s" % (url_parsed.scheme, url_parsed.hostname, port, url_parsed.path)

            if self._api_key:
                req_args["headers"].update({"X-Api-Key": self._api_key})

            cert      = req_args["kwargs"].pop("cert", None)
            transport = httpx.AsyncHTTPTransport(retries = self._retries,
                verify = verify, cert = cert)
            session   = httpx.AsyncClient(transport = transport)
            
            async with session:
                wait = req_args.pop("wait", None)
                if wait:
                    time.sleep(wait)

                auth     = req_args["kwargs"].pop("auth", None)

                request  = session.build_request(method, url,
                    headers = req_args["headers"],
                    *req_args["args"], **req_args["kwargs"])
                while request is not None:
                    response = await session.send(request, auth = auth)
                    request  = response.next_request

                return response

    def get(self, url, *args, **kwargs):
        """
        Dispatch a PUT request to the server.
        """
        return self.request("GET", url, *args, **kwargs)

    async def aget(self, url, *args, **kwargs):
        """
        Dispatch a PUT request to the server.
        """
        return await self.arequest("GET", url, *args, **kwargs)

    def post(self, url = None, *args, **kwargs):
        """
        Dispatch a POST request to the server.

        :param url: URL part (does not include the base URL).
        :param args: Arguments provided to ``api.request``
        :param kwargs: Keyword Arguments provided to ``api.request``
        """
        return self.request("POST", url, *args, **kwargs)
    
    async def apost(self, url = None, *args, **kwargs):
        """
        Dispatch a POST request to the server.

        :param url: URL part (does not include the base URL).
        :param args: Arguments provided to ``api.request``
        :param kwargs: Keyword Arguments provided to ``api.request``
        """
        return await self.arequest("POST", url, *args, **kwargs)

    def put(self, url, *args, **kwargs):
        """
        Dispatch a PUT request to the server.
        """
        response = self.request("PUT", url, *args, **kwargs)
        return response

    async def aput(self, url, *args, **kwargs):
        """
        Dispatch a PUT request to the server.
        """
        response = await self.arequest("PUT", url, *args, **kwargs)
        return response

    def patch(self, url, *args, **kwargs):
        """
        Dispatch a PATCH request to the server.
        """
        response = self.request("PATCH", url, *args, **kwargs)
        return response
    
    async def apatch(self, url, *args, **kwargs):
        """
        Dispatch a PATCH request to the server.
        """
        response = await self.arequest("PATCH", url, *args, **kwargs)
        return response

    def delete(self, url, *args, **kwargs):
        """
        Dispatch a DELETE request to the server.
        """
        response = self.request("DELETE", url, *args, **kwargs)
        return response

    async def adelete(self, url, *args, **kwargs):
        """
        Dispatch a DELETE request to the server.
        """
        response = await self.arequest("DELETE", url, *args, **kwargs)
        return response

    def ping(self):
        """
        Check if the URL is alive.

        Example::

            >>> import upyog
            >>> client = upyog.Client()
            >>> client.ping()
            'pong'
        """
        self.request("HEAD", "")
        return "pong"
    
    async def aping(self):
        """
        Check if the URL is alive.

        Example::

            >>> import upyog
            >>> client = upyog.Client()
            >>> client.ping()
            'pong'
        """
        await self.arequest("HEAD", "")
        return "pong"

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args, **kwargs):
        return await self.aclose()

    async def aclose(self):
        if self._async and self._session:
            return await self._session.aclose()

@ejectable(deps = ["BaseObject", "dict_items", "check_dict_struct", "import_or_raise", "squash", "upper"])
class RootClient(BaseObject):
    HTTP_METHODS = (
        "head",
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "options",
        "trace"
    )

    def __init__(self,
        auth = None,
        *args, **kwargs):
        super_ = super(RootClient, self)
        super_.__init__(*args, **kwargs)

        self._auth = auth

        self._setup()

    def _get_certificates(self):
        certs = []

        requests_ca_bundle = os.environ.get("REQUESTS_CA_BUNDLE", None)
        if requests_ca_bundle:
            certs.append(requests_ca_bundle)
        else:
            try:
                import certifi
                certs.append(certifi.where())
            except ImportError:
                pass

        return certs

    def _build_uri(self, path, **kwargs):
        variables = getattr(self, "variables", None) or {}
        args = {}

        for key, meta in dict_items(variables):
            if "default" in meta:
                args[key] = meta["default"]
            else:
                raise ValueError("No default value for variable %s." % key)

        for key, value in dict_items(kwargs):
            args[key] = value

        formatted = path.format(**args)

        return formatted
    
    def _build_url(self, uri):
        server =  getenv("API_SERVER")
        if server:
            server = self.servers.get(server)

        if not server:
            server = self.default_server

        url = server['url']
        if not url.endswith("/"):
            url += "/"
        
        if uri.startswith("/"):
            uri = uri[1:]

        url += uri

        return url
    
    def _build_request_kwargs(self, method, kwargs):
        method = lower(method)

        if method == "get" and "data" in kwargs:
            kwargs["params"] = kwargs.pop("data")

        if method == "post" and "data" in kwargs:
            kwargs["json"]   = kwargs.pop("data")

        if self.auth:
            kwargs["auth"] = self.auth

        return kwargs

    def _build_api_function(self, config):
        http_method = config.get("http_method") or "get"
        assert http_method in RootClient.HTTP_METHODS, f"Invalid HTTP method {http_method}."

        async def fn(**kwargs):
            parameters = config.get("parameters") or config.get("data") or {}
            if parameters:
                for key, meta in dict_items(parameters):
                    required = meta.get("required", False)

                    if required and not key in kwargs:
                        raise ValueError(f"Missing required parameter {key}.")

                    if key in kwargs:
                        value = kwargs[key]
                        if "target" in meta:
                            target = meta["target"]

                            setattr2(kwargs, target, value)

                            del kwargs[key]

                        ptype = meta.get("type", str)
                        if not isinstance(ptype, str):
                            if ptype == str and not isinstance(value, str):
                                raise ValueError(f"Parameter {key} must be a string.")
                        
                        if ptype == "choice":
                            if "values" not in meta:
                                raise ValueError(f"Missing 'values' for parameter {key}.")
                            
                            if value not in meta["values"]:
                                raise ValueError(f"Invalid value {value} for parameter {key}. Must be one of {meta['choices']}.")
                            
                    if key not in kwargs and "default" in meta:
                        kwargs[key] = meta["default"]

            uri = self._build_uri(config["path"], **kwargs)
            if self.async_:
                function_name = f"a{http_method}"

            function = getattr(self, function_name)

            response = await function(uri, data = kwargs)
            results  = []

            if "paginate" in config:
                key    = config["paginate"]
                rkey   = config["result"]

                result  = response[rkey]
                results.extend(result)

                while key in response and response[key]:
                    data     = { key: response[key] }
                    response = await function(uri, data = data)

                    result   = response[rkey]
                    results.extend(result)
            else:
                if "result" in config:
                    rkey   = config["result"]
                    result = response[rkey]
                else:
                    result = response

                results.append(result)

            return squash(results)

        if "description" in config:
            fn.__doc__ = config["description"]

        return fn
    
    def _handle_response(self, response):
        if response.status_code >= 400:
            try:
                output = response.json()
                self.log("error", f"Response Error: {output}")
            except:
                pass

        response.raise_for_status()

        result = response.json()

        return result

    def request(self, method, uri, **kwargs):
        url      = self._build_url(uri)
        kwargs   = self._build_request_kwargs(method, kwargs)

        response = self.session.request(method, url, **kwargs)

        return self._handle_response(response)

    def _setup(self):
        request_function = self.arequest if self.async_ else self.request

        def fn_http_method(method):
            fn_http_method.__doc__ = f"Dispatch a {upper(method)} request to the server."
            return lambda uri, **kwargs: request_function(method, uri, **kwargs)

        for http_method in RootClient.HTTP_METHODS:
            function_name = lower(http_method)
            if self.async_:
                function_name = f"a{function_name}"
            setattr(self, function_name, fn_http_method(http_method))

        api = getattr(self, "api", None) or autodict()
        for config in api["paths"]:
            function_name = config["function"]
            function = self._build_api_function(config)
            setattr(self, function_name, function)

    @property
    def default_server(self):
        if not hasattr(self, "servers"):
            raise ValueError("No `servers` defined.")
        
        servers = getattr(self, "servers")
        if isinstance(servers, str):
            servers = { "default": { "url": servers } }
        
        check_dict_struct(servers, {
            "default": {
                "url": str
            }
        })

        return servers["default"]

    @property
    def session(self):
        """
            Get the Session Object.
        """
        if not hasattr(self, "_session"):
            if self.async_:
                httpx     = import_or_raise("httpx")

                cert      = self._get_certificates()
                transport = httpx.AsyncHTTPTransport(
                    cert  = cert
                )
                session   = httpx.AsyncClient(transport = transport)
            else:
                requests  = import_or_raise("requests")
                session   = requests.Session()

            self._session = session

        return self._session

    @property
    def auth(self):
        return getattr(self, "_auth", None)
    
    @auth.setter
    def auth(self, value):
        self._auth = value

@ejectable(deps = ["RootClient"])
class AsyncBaseClient(RootClient):
    def __init__(self, *args, **kwargs):
        kwargs["async_"] = True
        super_ = super(AsyncBaseClient, self)
        super_.__init__(*args, **kwargs)

    async def arequest(self, method, uri, *args, **kwargs):
        """"
            Dispatch a request to the server.

            Parameters:
                method (str): HTTP Method.
                uri (str): URI.
        """
        url      = self._build_url(uri)
        kwargs   = self._build_request_kwargs(method, kwargs)

        response = await self.session.request(method, url, *args, **kwargs)
        
        return self._handle_response(response)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args, **kwargs):
        return await self.aclose()

    async def aclose(self):
        if self.session:
            return await self.session.aclose()

@ejectable(deps = ["sequencify", "BaseObject"])
class SuperClient(BaseObject):
    def __init__(self,
        on_error = None, *args, **kwargs):
        super_ = super(SuperClient, self)
        super_.__init__(*args, **kwargs)

        self.on_error = on_error

        self._setup()

    def _setup(self):
        if not hasattr(self, "client"):
            raise ValueError("No `client` defined.")
        
    def __enter__(self):
        return self
    
    def __exit__(self, *args, **kwargs):
        return self.close()

    def close(self):
        raise NotImplementedError("close method not implemented.")

@ejectable(deps = ["SuperClient"])
class SuperAsyncClient(SuperClient):
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, *args):
        return await self.aclose()
    
    def aclose(self):
        raise NotImplementedError("close method not implemented.")