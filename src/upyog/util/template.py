# imports - compat imports
from upyog._compat import PY2

# imports - standard imports
import os.path as osp, upyog as upy

if PY2:
    import cgi as module_escape
else:
    import html as module_escape

# imports - module imports
from upyog.util.system import read
from upyog.util.array  import sequencify
from upyog.util.imports import import_or_raise
from upyog.log         import get_logger
from upyog.exception   import TemplateNotFoundError
from upyog.util.string import _REGEX_HTML
from upyog._compat     import iteritems, StringIO
from upyog.config      import PATH
import upyog as upy
from upyog.util.eject import ejectable

logger = get_logger()

JINJA_TEMPLATE_EXTENSIONS = (".jinja", ".jinja2", ".j2")

@ejectable(deps = ["read", "import_or_raise", "sequencify"])
def render_jinja_template(template, context = None, template_dirs = None):
    import os.path as osp
    from io import StringIO

    jinja2 = import_or_raise("jinja2", "Jinja2")
    template_dirs = sequencify(template_dirs or [])

    exists = False

    if osp.exists(template):
        exists = True
    else:
        for ext in JINJA_TEMPLATE_EXTENSIONS:
            path = f"{template}{ext}"
            if osp.exists(path):
                exists   = True
                template = path
                break

    if not exists:
        raise TemplateNotFoundError("Template %s not found." % template)

    content = read(template)

    context = context or {}
    context = {
        **context,
        "upy": globals().get("upy")
    }
    
    with StringIO() as out:
        args = {}

        if template_dirs:
            args["loader"] = jinja2.FileSystemLoader(template_dirs)

        from jinja2 import select_autoescape
        autoescape = select_autoescape(
            ["html", "xml"]
        )

        env = jinja2.Environment(**args, autoescape = None)

        env.from_string(content) \
            .stream(context) \
            .dump(out)

        return out.getvalue()

@ejectable(deps = ["render_jinja_template", "sequencify"])
def render_template(template, context = None, dirs = [ ], **kwargs):
    """
    Renders a template. The template must be of the string format. For more 
    details, see 
    https://docs.python.org/3.4/library/string.html#string-formatting.

    :param template: Path to template file.
    :param context: The context passed to the template.
    :param dirs: Path/List of Directory Paths to search for templates.

    :return: Returns the rendered template.
    :rtype: str

    Usage::

        >>> from ccapi.template import render_template
        >>> render_template("test.html", context = dict(name = "Test"))
        'Hello, Test!'
        >>> render_template("test.html", name = "Test")
        'Hello, Test!'
        >>> render_template("foobar.html", dirs = "templates", bar = "baz")
        'foobaz'
    """
    import os.path as osp

    jinja = kwargs.get("jinja", False)
    if jinja:
        template_dirs = kwargs.get("template_dirs")
        rendered = render_jinja_template(template, context = context,
            template_dirs = template_dirs)
    else:
        dirs  = sequencify(dirs)
        if PATH["TEMPLATES"] not in dirs:
            dirs.append(PATH["TEMPLATES"])

        dirs = [osp.abspath(dir_) for dir_ in dirs]

        logger.info("Searching for templates within directories: %s" % dirs)

        path = None
        for dir_ in dirs:
            temp = osp.join(dir_, template)
            if osp.exists(temp):
                path = temp
                break
        
        if not path:
            as_string = kwargs.get("as_string", False)

            if as_string:
                rendered = template
            else:
                raise TemplateNotFoundError("Template %s not found." % template)
        else:
            html     = read(path)
            rendered = html

        if not context:
            context = kwargs

        if context:
            escape = False

            for name, item in iteritems(context):
                item = str(item)

                if escape:
                    item = module_escape.escape(item)
                
                context[name] = item

            rendered = rendered.format(**context)

    output = kwargs.get("output")
    if output:
        force = kwargs.get("force", False)
        upy.write(output, rendered, force = force)
    
    return rendered