from .parser import lexer, LookAheadIterator
from .generator import AsciiDocGenerator

from argparse import ArgumentParser
import sys

def main():
    ap = ArgumentParser('help2adoc')
    ap.add_argument('file')
    args = ap.parse_args()
    with open(args.file, 'r') as f:
        tokens = LookAheadIterator(lexer(f))
        AsciiDocGenerator(sys.stdout.write).parse_help(tokens)
        token = tokens.lookahead()
        if token is None:
            return
        epilog_start = token.lineno
        f.seek(0)
        for i in range(epilog_start):
            next(f)
        print('....')
        for line in f:
            print(line, end='')
        print('....')


if __name__ == '__main__':
    main()
