from __future__ import unicode_literals

from six import string_types
from prompt_toolkit.completion import Completer, Completion

__all__ = (
    'CrmshCompleter',
)

class CrmshCompleter(Completer):

    def __init__(self, func):
        self.func = func
        self.word_pool_before = []

    def get_completions(self, document, complete_event):
        word_before_cursor = document.text_before_cursor
        def word_matches(word):
            if word_before_cursor:
                if word_before_cursor.endswith(" "):
                    return False, 0
                return word.startswith(word_before_cursor.split()[-1]), len(word_before_cursor.split()[-1])
            else:
                return word.startswith(word_before_cursor), 0

        self.word_pool = self.func(word_before_cursor)
        if not self.word_pool:
            for a in self.word_pool_before:
                res, len_word = word_matches(a)
                if res:
                    yield Completion(a, -len_word)
        else:
            self.word_pool_before = self.word_pool

        for a in sorted(self.word_pool):
            res, len_word = word_matches(a)
            if res:
                if a.endswith("="):
                    yield Completion(a, -len_word)
                yield Completion(a+' ', -len_word)
            if not res and len_word == 0:
                yield Completion(a+' ', -len_word)
         

