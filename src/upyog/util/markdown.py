from upyog.util.eject import ejectable
from upyog.util.imports import import_handler

@ejectable()
def md_linkify(text, url):
    return f"[{text}]({url})"

@ejectable(deps = ["import_handler"])
def md2html(md):
    markdown = import_handler("markdown")
    return markdown.markdown(md)