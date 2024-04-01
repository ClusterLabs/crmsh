from .parser import Parser

import typing
import re


class AsciiDocGenerator(Parser):
    USAGE_RE = re.compile('^usage:\\s*')

    def __init__(self, output: typing.Callable[[str], None]):
        self.output = output

    def on_usage(self, text: str):
        usage = text[self.USAGE_RE.match(text).end():]
        self.output('Usage:\n\n ')
        self.output(usage)
        self.output('\n\n')

    def on_paragraph(self, text: str):
        self.output(self.escape(text))
        self.output('\n\n')

    def enter_options(self):
        self.output('Options:\n\n')

    def exit_options(self):
        self.output('\n')

    def on_option(self, option: str, help: str):
        self.output('* `+++')
        self.output(option)
        self.output('+++`: ')
        self.output(self.escape(help))
        self.output('\n\n')

    def enter_option_group(self, name: str):
        self.output(name)
        self.output(':\n\n')

    def exit_option_group(self, name: str):
        self.output('\n')

    def enter_description(self):
        pass

    def exit_description(self):
        pass

    def escape(self, text: str):
        # TODO
        return text
