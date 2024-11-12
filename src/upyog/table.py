from __future__ import absolute_import

# imports - compatibility imports
from upyog._compat     import zip_longest

# imports - module imports
from upyog.util.string import strip_ansi
import upyog as upy
from upyog.util.eject import ejectable

def _sanitize_string(string):
    """
    Helper for tabulate to sanitize strings.
    """
    string = str(string)
    string = strip_ansi(string)
    return string

@ejectable(deps = ["strip_ansi", "zip_longest"])
def tabulate(rows):
    # Shamelessly taken from: https://git.io/fARTL (pip)
    # Also: https://git.io/fARTY (yarn)
    # Yo, WTF is wrong with git.io and its "fart" filled short urls?

    sizes  = [0] * max(len(x) for x in rows)
    for row in rows:
        sizes = [max(s, len(str(_sanitize_string(c if c else "")))) for s, c in zip_longest(sizes, row)]

    result = [ ]
    for row in rows:
        display = " ".join([str(c) + " " * (s - len(_sanitize_string(c if c else ""))) if c is not None else ""
                            for s, c in zip_longest(sizes, row)])
        result.append(display)

    return result, sizes

@ejectable(deps = ["lvalues", "lkeys", "tabulate"])
class Table(object):
    def __init__(self, rows = [ ], header = None, type_ = "rows"):
        self._type  = type_
        self.header = header or [ ]

        self.rows   = [ ]

        for row in rows:
            self.insert(row)

    @property
    def empty(self):
        _empty = len(self) == 0
        return _empty

    def insert(self, row):
        if self._type == "record":
            values = upy.lvalues(row)
            if not self.header:
                self.header = upy.lkeys(row)
        else:
            values = row

        self.rows.append(values)

    def render(self, header = True):
        string = ""

        _rows  = self.rows[:]
        
        if header and self.header:
            _rows.insert(0, self.header)

        if _rows:
            tabulated, sizes = tabulate(_rows)
            
            # divider
            if header:
                tabulated.insert(1, " ".join(map(lambda x: "-" * x, sizes)))

            string  = "\n".join(tabulated)

        return string

    def __len__(self):
        length = len(self.rows)
        return length
    
@ejectable(deps = ["Table"])
def render_table(rows, header = None):
    table  = Table(rows, header = header, type_ = "record")
    string = table.render()
    print(string)