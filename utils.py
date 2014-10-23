import re
_slugify_strip_re = re.compile(r'[^\w\s-]')
_slugify_hyphenate_re = re.compile(r'[-\s]+')

def _slugify(value):
    """
    Normalizes string, converts to lowercase, removes non-alpha characters,
    and converts spaces to hyphens.
    
    From Django's "django/template/defaultfilters.py".
    """
    import unicodedata
    if not isinstance(value, unicode):
        value = unicode(value)
    value = unicodedata.normalize('NFKD', value).encode('ascii', 'ignore')
    value = unicode(_slugify_strip_re.sub('', value).strip().lower())
    return _slugify_hyphenate_re.sub('-', value)


def invertHex(hexNumber):
    hexNumber = hexNumber.replace("#", "")
    r = hexNumber[0:2]
    inverse_r = "{0:0{1}x}".format(abs(int(r, 16) - 255),2)
    g = hexNumber[2:4]
    inverse_g = "{0:0{1}x}".format(abs(int(g, 16) - 255),2)
    b = hexNumber[4:6]
    inverse_b = "{0:0{1}x}".format(abs(int(b, 16) - 255),2)
    return "#%s%s%s"%(inverse_r, inverse_g, inverse_b)

