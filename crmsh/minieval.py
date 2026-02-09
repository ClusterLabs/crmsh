# Copyright (C) 2013-2017 Daniel Fairhead
# Copyright (C) 2017 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

"""
Based on simpleeval:

SimpleEval - (C) 2013-2017 Daniel Fairhead
-------------------------------------

An short, easy to use, safe and reasonably extensible expression evaluator.
Designed for things like in a website where you want to allow the user to
generate a string, or a number from some other input, without allowing full
eval() or other unsafe or needlessly complex linguistics.

-------------------------------------

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

-------------------------------------

Initial idea copied from J.F. Sebastian on Stack Overflow
( http://stackoverflow.com/a/9558001/1973500 ) with
modifications and many improvments.

-------------------------------------
Contributors:
- corro (Robin Baumgartner) (py3k)
- dratchkov (David R) (nested dicts)
- marky1991 (Mark Young) (slicing)
- T045T (Nils Berg) (!=, py3kstr, obj.
- perkinslr (Logan Perkins) (.__globals__ or .func_ breakouts)
- impala2 (Kirill Stepanov) (massive _eval refactor)
- gk (ugik) (Other iterables than str can DOS too, and can be made)
- daveisfera (Dave Johansen) 'not' Boolean op, Pycharm and pep8 fixes.

-------------------------------------
Usage:

>>> s = SimpleEval()
>>> s.eval("20 + 30")
50

You can add your own functions easily too:

if file.txt contents is "11"

>>> def get_file():
        with open("file.txt",'r') as f:
            return f.read()

    s.functions["get_file"] = get_file
    s.eval("int(get_file()) + 31")
42

For more information, see the full package documentation on pypi, or the github
repo.

-----------

If you don't need to re-use the evaluator (with it's names, functions, etc),
then you can use the simple_eval() function:

>>> simple_eval("21 + 19")
40

You can pass names, operators and functions to the simple_eval function as
well:

>>> simple_eval("40 + two", names={"two": 2})
42

"""

import ast
import sys
import operator as op

########################################
# Module wide 'globals'

MAX_STRING_LENGTH = 100000
DISALLOW_PREFIXES = ['_', 'func_']
DISALLOW_METHODS = ['format']

PYTHON3 = sys.version_info[0] == 3

########################################
# Exceptions:


class InvalidExpression(Exception):
    """ Generic Exception """
    pass


class NameNotDefined(InvalidExpression):
    """ a name isn't defined. """
    def __init__(self, name, expression):
        self.name = name
        self.message = "'{0}' is not defined for expression '{1}'".format(
            name, expression)
        self.expression = expression

        # pylint: disable=bad-super-call
        super(InvalidExpression, self).__init__(self.message)


class AttributeDoesNotExist(InvalidExpression):
    """attribute does not exist"""
    def __init__(self, attr, expression):
        self.message = \
            "Attribute '{0}' does not exist in expression '{1}'".format(
                attr, expression)
        self.attr = attr
        self.expression = expression


class FeatureNotAvailable(InvalidExpression):
    """ What you're trying to do is not allowed. """
    pass


class IterableTooLong(InvalidExpression):
    """ That iterable is **way** too long, baby. """
    pass


########################################
# Defaults for the evaluator:

DEFAULT_OPERATORS = {ast.Eq: op.eq, ast.NotEq: op.ne,
                     ast.Gt: op.gt, ast.Lt: op.lt,
                     ast.GtE: op.ge, ast.LtE: op.le,
                     ast.Not: op.not_,
                     ast.USub: op.neg, ast.UAdd: op.pos,
                     ast.In: lambda x, y: op.contains(y, x),
                     ast.NotIn: lambda x, y: not op.contains(y, x),
                     ast.Is: lambda x, y: x is y,
                     ast.IsNot: lambda x, y: x is not y,
                     }

DEFAULT_NAMES = {"True": True, "False": False}

########################################
# And the actual evaluator:


class SimpleEval(object):  # pylint: disable=too-few-public-methods
    """ A very simple expression parser.
        >>> s = SimpleEval()
        >>> s.eval("20 + 30 - ( 10 * 5)")
        0
        """
    expr = ""

    def __init__(self, names):
        """
            Create the evaluator instance.  Set up valid operators (+,-, etc)
            functions (add, random, get_val, whatever) and names. """

        operators = DEFAULT_OPERATORS
        names = names.copy()
        names.update(DEFAULT_NAMES)

        self.operators = operators
        self.names = names

        self.nodes = {
            ast.Constant: self._eval_constant,
            ast.Name: self._eval_name,
            ast.UnaryOp: self._eval_unaryop,
            ast.BinOp: self._eval_binop,
            ast.BoolOp: self._eval_boolop,
            ast.Compare: self._eval_compare,
            ast.IfExp: self._eval_ifexp,
            ast.keyword: self._eval_keyword,
            ast.Subscript: self._eval_subscript,
            ast.Attribute: self._eval_attribute,
            ast.Index: self._eval_index,
            ast.Slice: self._eval_slice,
        }

        # py3k stuff:
        if hasattr(ast, 'NameConstant'):
            self.nodes[ast.NameConstant] = self._eval_constant
        elif isinstance(self.names, dict) and "None" not in self.names:
            self.names["None"] = None

        # py3.14 completely dropped ast.Num and ast.Str
        # in favor of ast.Constant that encodes different types of value
        # See https://docs.python.org/3/whatsnew/3.14.html#id9
        if hasattr(ast, 'Str'):
            self.nodes[ast.Str] = self._eval_str
        if hasattr(ast, 'Num'):
            self.nodes[ast.Num] = self._eval_num

    def evaluate(self, expr):
        """ evaluate an expresssion, using the operators, functions and
            names previously set up. """

        # set a copy of the expression aside, so we can give nice errors...

        self.expr = expr

        # and evaluate:
        return self._eval(ast.parse(expr.strip()).body[0].value)

    def _eval(self, node):
        """ The internal evaluator used on each node in the parsed tree. """

        try:
            handler = self.nodes[type(node)]
        except KeyError:
            raise FeatureNotAvailable("Sorry, {0} is not available in this "
                                      "evaluator".format(type(node).__name__))

        return handler(node)

    @staticmethod
    def _eval_num(node):
        return node.n

    @staticmethod
    def _eval_str(node):
        if len(node.s) > MAX_STRING_LENGTH:
            raise IterableTooLong("String Literal in statement is too long!"
                                  " ({0}, when {1} is max)".format(
                                      len(node.s), MAX_STRING_LENGTH))
        return node.s

    @staticmethod
    def _eval_constant(node):
        if (hasattr(node.value, '__len__') and
                len(node.value) > MAX_STRING_LENGTH):
            raise IterableTooLong("Literal in statement is too long!"
                                  " ({0}, when {1} is max)"
                                  "".format(len(node.value),
                                            MAX_STRING_LENGTH))
        return node.value

    def _eval_unaryop(self, node):
        return self.operators[type(node.op)](self._eval(node.operand))

    def _eval_binop(self, node):
        return self.operators[type(node.op)](self._eval(node.left),
                                             self._eval(node.right))

    def _eval_boolop(self, node):
        if isinstance(node.op, ast.And):
            vout = False
            for value in node.values:
                vout = self._eval(value)
                if not vout:
                    return False
            return vout
        elif isinstance(node.op, ast.Or):
            for value in node.values:
                vout = self._eval(value)
                if vout:
                    return vout
            return False

    def _eval_compare(self, node):
        left = self._eval(node.left)
        for operation, comp in zip(node.ops, node.comparators):
            right = self._eval(comp)
            if self.operators[type(operation)](left, right):
                left = right  # Hi Dr. Seuss...
            else:
                return False
        return True

    def _eval_ifexp(self, node):
        return self._eval(node.body) if self._eval(node.test) \
                                         else self._eval(node.orelse)

    def _eval_keyword(self, node):
        return node.arg, self._eval(node.value)

    def _eval_name(self, node):
        try:
            # This happens at least for slicing
            # This is a safe thing to do because it is impossible
            # that there is a true exression assigning to none
            # (the compiler rejects it, so you can't even
            # pass that to ast.parse)
            if isinstance(self.names, dict):
                return self.names[node.id]
            elif callable(self.names):
                return self.names(node)
            else:
                raise InvalidExpression('Trying to use name (variable) "{0}"'
                                        ' when no "names" defined for'
                                        ' evaluator'.format(node.id))

        except KeyError:
            if node.id in self.functions:
                return self.functions[node.id]

            raise NameNotDefined(node.id, self.expr)

    def _eval_subscript(self, node):

        container = self._eval(node.value)
        key = self._eval(node.slice)
        try:
            return container[key]
        except KeyError:
            raise

    def _eval_attribute(self, node):
        for prefix in DISALLOW_PREFIXES:
            if node.attr.startswith(prefix):
                raise FeatureNotAvailable(
                    "Sorry, access to __attributes "
                    " or func_ attributes is not available. "
                    "({0})".format(node.attr))
        if node.attr in DISALLOW_METHODS:
            raise FeatureNotAvailable(
                    "Sorry, this method is not available. "
                    "({0})".format(node.attr))

        try:
            return self._eval(node.value)[node.attr]
        except (KeyError, TypeError):
            pass

        # Maybe the base object is an actual object, not just a dict
        try:
            return getattr(self._eval(node.value), node.attr)
        except (AttributeError, TypeError):
            pass

        # If it is neither, raise an exception
        raise AttributeDoesNotExist(node.attr, self.expr)

    def _eval_index(self, node):
        return self._eval(node.value)

    def _eval_slice(self, node):
        lower = upper = step = None
        if node.lower is not None:
            lower = self._eval(node.lower)
        if node.upper is not None:
            upper = self._eval(node.upper)
        if node.step is not None:
            step = self._eval(node.step)
        return slice(lower, upper, step)


def minieval(expr, env):
    """
    Given a dict of variable -> value mapping in env,
    parse and evaluate the expression in expr
    """
    return SimpleEval(env).evaluate(expr)
