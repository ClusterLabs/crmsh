#!/usr/bin/env python3
import typing
import re
import io


class Token:
    def __init__(self, lineno: int, tpe: str, text: str):
        self.tpe = tpe
        self.lineno = lineno
        self.text = text

    def __str__(self):
        return f'Token(tpe={self.tpe}, text={self.text})'


class EmptyLineToken(Token):
    def __init__(self, lineno: int):
        super().__init__(lineno, 'emptyline', '')


class TextToken(Token):
    def __init__(self, lineno: int, indent: int, text: str):
        super().__init__(lineno, 'text', text)
        self.indent = indent


class LogToken(Token):
    def __init__(self, lineno: int, text: str):
        super().__init__(lineno, 'log', text)


class UsageToken(Token):
    def __init__(self, lineno: int, text: str):
        super().__init__(lineno, 'usage', text)


class OptionsToken(Token):
    def __init__(self, lineno: int, text: str):
        super().__init__(lineno, 'options', text)


class OptionToken(Token):
    def __init__(self, lineno: int, text: str):
        super().__init__(lineno, 'option', text)


def lexer(lines: typing.Iterator[str]):
    for lineno, line in enumerate(lines):
        line = line.rstrip()
        if not line:
            yield EmptyLineToken(lineno)
        elif re.match('(?:\033\\[\\d+m)?(?:INFO|ERROR)(?:\033\\[0m)?: ', line):
            pass
        elif re.match('usage: ', line):
            yield UsageToken(lineno, line)
        elif re.match('options:', line):
            yield OptionsToken(lineno, line)
        elif re.match('\\s+-', line):
            yield OptionToken(lineno, line)
        else:
            indent = re.search('\\S', line).start()
            yield TextToken(lineno, indent, line)


T = typing.TypeVar('T')


class LookAheadIterator(typing.Generic[T]):
    def __init__(self, it: typing.Iterator[T]):
        self._it = it
        self._lookahead_buffer = list()
        self._lookahead_index = -1

    def lookahead(self):
        if self._lookahead_index + 1 == len(self._lookahead_buffer):
            try:
                ret = next(self._it)
                self._lookahead_index += 1
                self._lookahead_buffer.append(ret)
                return ret
            except StopIteration:
                return None
        else:
            self._lookahead_index += 1
            return self._lookahead_buffer[self._lookahead_index]

    def consume(self):
        self._lookahead_buffer = self._lookahead_buffer[self._lookahead_index+1:]
        self._lookahead_index = -1

    def rollback(self):
        self._lookahead_index -= 1

    def reset(self):
        self._lookahead_index = -1


class SyntaxErrorException(Exception):
    pass


class Parser:
    def on_usage(self, text: str):
        print('<usage/>')

    def enter_description(self):
        print('<description>')

    def exit_description(self):
        print('</description>')

    def on_paragraph(self, text: str):
        print(f'<paragraph>{text}</paragraph>')

    def enter_options(self):
        print('<options>')

    def exit_options(self):
        print('</options>')

    def enter_option_group(self, name: str):
        print(f'<option_group name={name}>')

    def exit_option_group(self, name: str):
        print(f'</option_group name={name}>')

    def on_option(self, option: str, help: str):
        print(f'<option name={option}/>')

    def parse_help(self, tokens: LookAheadIterator[Token]):
        self.parse_usage(tokens)
        self.parse_description(tokens)
        self.parse_options(tokens)
        tokens.reset()

    class MatchFailure(Exception):
        pass

    def parse_usage(self, tokens: LookAheadIterator[Token]):
        token = tokens.lookahead()
        self.assert_token_tpe('usage', token)
        buf = io.StringIO()
        buf.write(token.text)
        while True:
            token = tokens.lookahead()
            if token is None:
                tokens.consume()
                self.on_usage(buf.getvalue())
            elif token.tpe == 'text':
                buf.write(' ')
                buf.write(token.text[token.indent:])
            else:
                self.assert_token_tpe('emptyline', token)
                tokens.rollback()
                self.parse_emptyline(tokens)
                self.on_usage(buf.getvalue())
                break

    def parse_description(self, tokens: LookAheadIterator[Token]):
        result = self.parse_paragraph(tokens)
        if result is not None:
            indent, paragraph = result
            self.enter_description()
            tokens.consume()
            self.on_paragraph(paragraph)
            while True:
                ret = self.parse_paragraph(tokens)
                if ret is None:
                    self.exit_description()
                    return
                indent, text = ret
                tokens.consume()
                self.on_paragraph(text)


    def parse_options(self, tokens: LookAheadIterator[Token]):
        token = tokens.lookahead()
        if token.tpe != 'options':
            return
        else:
            self.enter_options()
            self.parse_option_group(tokens)
            while self.parse_named_option_group(tokens):
                pass
            self.exit_options()

    def parse_option_group(self, tokens: LookAheadIterator[Token]):
        while True:
            ret = self.parse_option(tokens)
            if ret is None:
                break
            option, help = ret
            self.on_option(option, help)

    def parse_option(self, tokens: LookAheadIterator[Token]):
        token = tokens.lookahead()
        if token is not None and token.tpe == 'option':
            match = re.match(
                '\\s+((?:-[a-zA-Z]|--[-a-zA-Z0-9]+)(?:\\s[^, ]+)?(?:,\\s+--[-a-zA-Z0-9]+(?:\\s[^, ]+)?)?)\\s*',
                token.text,
            )
            if match is None:
                tokens.rollback()
                return None
            option = match.group(1)
            buf = io.StringIO()
            buf.write(token.text[match.end():])
            while True:
                token = tokens.lookahead()
                if token is None:
                    tokens.consume()
                    break
                elif token.tpe != 'text':
                    tokens.rollback()
                    break
                else:
                    tokens.consume()
                    if buf.tell() != 0:
                        buf.write(' ')
                    buf.write(token.text[token.indent:])
            return option, buf.getvalue()

    def parse_named_option_group(self, tokens: LookAheadIterator[Token]):
        token = tokens.lookahead()
        if token is None:
            tokens.rollback()
            return
        elif token.tpe == 'emptyline':
            tokens.rollback()
            self.parse_emptyline(tokens)
        if token.tpe == 'text' and token.indent == 0 and token.text[-1] == ':':
            group_name = token.text[:-1]
            description = list()
            while True:
                ret = self.parse_paragraph(tokens)
                if ret is None:
                    break
                indent, text = ret
                description.append(text)
            ret = self.parse_option(tokens)
            if ret is None:
                tokens.reset()
                return
            else:
                self.enter_option_group(group_name)
                for paragraph in description:
                    self.on_paragraph(paragraph)
                option, help = ret
                self.on_option(option, help)
                tokens.consume()
                while True:
                    ret = self.parse_option(tokens)
                    if ret is None:
                        break
                    option, help = ret
                    self.on_option(option, help)
                    tokens.consume()
                self.parse_emptyline(tokens)
                self.exit_option_group(group_name)
                tokens.consume()
            return True
        else:
            tokens.rollback()
            return False

    @classmethod
    def assert_token_tpe(cls, tpe: str, token: Token):
        if token.tpe != tpe:
            raise SyntaxErrorException(f'Expected: <{tpe}>. Actural: {token.text}')

    def parse_log(self, tokens: LookAheadIterator[Token]):
        # TODO: remove me
        while True:
            token = tokens.lookahead()
            if token.tpe == 'log':
                tokens.consume()
            else:
                return

    def parse_paragraph(self, tokens: LookAheadIterator[Token]):
        buf = io.StringIO()
        indent = -1
        while True:
            token = tokens.lookahead()
            if token is None:
                tokens.consume()
                break
            if token.tpe != 'text':
                tokens.rollback()
                break
            new_indent = token.indent
            if indent == -1:
                indent = new_indent
                buf.write(token.text[indent:])
            elif new_indent == indent:
                buf.write(' ')
                buf.write(token.text[indent:])
            else:
                tokens.rollback()
                break
        if indent == -1:
            return None
        else:
            token = tokens.lookahead()
            if token is not None:
                tokens.rollback()
                self.parse_emptyline(tokens)
            return indent, buf.getvalue()

    def parse_emptyline(self, tokens: LookAheadIterator[Token]):
        while True:
            token = tokens.lookahead()
            if token.tpe != 'emptyline':
                tokens.rollback()
                break


def main():
    import sys
    stdin = sys.stdin
    with open(3, buffering=1) as stdin:
        tokens = LookAheadIterator(lexer(stdin))
        Parser().parse_help(tokens)
        print('epilog starts at line {}'.format(tokens.lookahead().lineno))


if __name__ == '__main__':
    main()
