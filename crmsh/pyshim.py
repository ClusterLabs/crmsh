import functools


try:
    from functools import cache
except ImportError:
    def cache(f):
        cached_return_value = dict()

        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            nonlocal cached_return_value
            key = (tuple(args), tuple(sorted(kwargs.items())))
            try:
                return cached_return_value[key]
            except KeyError:
                ret = f(*args, **kwargs)
                cached_return_value[key] = ret
                return ret

        return wrapper
