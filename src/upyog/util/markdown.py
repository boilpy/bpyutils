from upyog.util.eject import ejectable

@ejectable()
def md_linkify(text, url):
    return f"[{text}]({url})"