# -*- coding: utf-8 -*-
"""
    pygments.lexers.dsls
    ~~~~~~~~~~~~~~~~~~~~

    Lexers for various domain-specific languages.

    :copyright: Copyright 2006-2015 by the Pygments team, see AUTHORS.
    :license: BSD, see LICENSE for details.
"""


import re

from pygments.lexer import RegexLexer, bygroups, words, include, default
from pygments.token import Text, Comment, Operator, Keyword, Name, String, \
    Number, Punctuation, Literal, Whitespace

__all__ = ['CrmshLexer']


class CrmshLexer(RegexLexer):
    """
    Lexer for `crmsh <http://crmsh.github.io/>`_ configuration files
    for Pacemaker clusters.

    .. versionadded:: 2.1
    """
    name = 'Crmsh'
    aliases = ['crmsh', 'pcmk']
    filenames = ['*.crmsh', '*.pcmk']
    mimetypes = []

    elem = words((
        'node', 'primitive', 'group', 'clone', 'ms', 'location',
        'colocation', 'order', 'fencing_topology', 'rsc_ticket',
        'rsc_template', 'property', 'rsc_defaults',
        'op_defaults', 'acl_target', 'acl_group', 'user', 'role',
        'tag'), suffix=r'(?![\w#$-])')
    sub = words((
        'params', 'meta', 'operations', 'op', 'rule',
        'attributes', 'utilization'), suffix=r'(?![\w#$-])')
    acl = words(('read', 'write', 'deny'), suffix=r'(?![\w#$-])')
    bin_rel = words(('and', 'or'), suffix=r'(?![\w#$-])')
    un_ops = words(('defined', 'not_defined'), suffix=r'(?![\w#$-])')
    date_exp = words(('in_range', 'date', 'spec', 'in'), suffix=r'(?![\w#$-])')
    acl_mod = (r'(?:tag|ref|reference|attribute|type|xpath)')
    bin_ops = (r'(?:lt|gt|lte|gte|eq|ne)')
    val_qual = (r'(?:string|version|number)')
    rsc_role_action=(r'(?:Master|Started|Slave|Stopped|'
        r'start|promote|demote|stop)')

    tokens = {
        'root': [
            (r'^#.*\n?', Comment),
            # attr=value (nvpair)
            (r'([\w#$-]+)(=)("(?:""|[^"])*"|\S+)',
                bygroups(Name.Attribute, Punctuation, String)),
            # need this construct, otherwise numeric node ids
            # are matched as scores
            # elem id:
            (r'(node)(\s+)([\w#$-]+)(:)',
                bygroups(Keyword, Whitespace, Name, Punctuation)),
            # scores
            (r'([+-]?([0-9]+|inf)):', Number),
            # keywords (elements and other)
            (elem, Keyword),
            (sub, Keyword),
            (acl, Keyword),
            # binary operators
            (r'(?:%s:)?(%s)(?![\w#$-])' % (val_qual,bin_ops),
                Operator.Word),
            # other operators
            (bin_rel, Operator.Word),
            (un_ops, Operator.Word),
            (date_exp, Operator.Word),
            # builtin attributes (e.g. #uname)
            (r'#[a-z]+(?![\w#$-])', Name.Builtin),
            # acl_mod:blah
            (r'(%s)(:)("(?:""|[^"])*"|\S+)' % acl_mod,
                bygroups(Keyword, Punctuation, Name)),
            # rsc_id[:(role|action)]
            # NB: this matches all other identifiers
            (r'([\w#$-]+)(?:(:)(%s))?(?![\w#$-])' % rsc_role_action,
                bygroups(Name, Punctuation, Operator.Word)),
            # punctuation
            (r'(\\(?=\n)|[[\](){}/:@])', Punctuation),
            (r'\s+|\n', Whitespace),
        ],
    }
