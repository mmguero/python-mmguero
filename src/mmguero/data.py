"""Dict/collection manipulation utilities, plus JSON load/serialize helpers."""

import json

from datetime import datetime
from types import GeneratorType, FunctionType, LambdaType

from .clihints import _exclude_from_cli


try:
    from collections.abc import Iterable
except ImportError:
    from collections import Iterable


try:
    from datetime import UTC as utc_time_zone
except ImportError:
    from datetime import timezone

    utc_time_zone = timezone.utc


@_exclude_from_cli
def deep_get(d, keys, default=None):
    """Safe deep get for a dictionary.

    Example:
      d = {'meta': {'status': 'OK', 'status_code': 200}}
      deep_get(d, ['meta', 'status_code'])          # => 200
      deep_get(d, ['garbage', 'status_code'])       # => None
      deep_get(d, ['meta', 'garbage'], default='-') # => '-'

    Args:
        d (dict): Dictionary to read from.
        keys (any): A single key, or a sequence of keys describing the nested path.
        default (any, optional): Value to return if the path doesn't exist. Defaults to None.

    Returns:
        any: The value at the nested path, or `default` if not found.
    """
    k = get_iterable(keys)
    if d is None:
        return default
    if not keys:
        return d
    return deep_get(d.get(k[0]), k[1:], default)


@_exclude_from_cli
def deep_set(d, keys, value, delete_if_none=False):
    """Convenience routine for setting a value into a dictionary at a nested path.

    Args:
        d (dict): Dictionary to modify in place.
        keys (any): A single key, or a sequence of keys describing the nested path.
        value (any): Value to set at that path.
        delete_if_none (bool, optional): If True and `value` is None, remove the key instead of setting it. Defaults to False.
    """
    k = get_iterable(keys)
    for key in k[:-1]:
        if (key not in d) or (not isinstance(d[key], dict)):
            d[key] = dict()
        d = d[key]
    d[k[-1]] = value
    if delete_if_none and (value is None):
        d.pop(k[-1], None)


@_exclude_from_cli
def deep_merge(source, destination):
    """Recursively merge `source` into `destination`, with `source` values taking precedence.

    Args:
        source (dict): Dictionary whose values take precedence.
        destination (dict): Dictionary to merge into, modified in place.

    Returns:
        dict: `destination`, after merging.
    """
    for key, value in source.items():
        if isinstance(value, dict) and isinstance(destination.get(key), dict):
            destination[key] = deep_merge(value, destination[key])
        else:
            destination[key] = value
    return destination


@_exclude_from_cli
def deep_merge_in_place(source, destination):
    """Recursively merge `source` into `destination` in place.

    Args:
        source (dict): Dictionary whose values take precedence.
        destination (dict): Dictionary to merge into, modified in place.
    """
    for key, value in source.items():
        if isinstance(value, dict) and isinstance(destination.get(key), dict):
            deep_merge(value, destination[key])
        else:
            destination[key] = value


@_exclude_from_cli
def dict_search(d, target):
    """Recursive dictionary key search.

    Args:
        d (dict): Dictionary (possibly nested) to search.
        target (any): Key to search for at any depth.

    Returns:
        list: All values found under a key matching `target`.
    """
    val = filter(
        None, [[b] if a == target else dict_search(b, target) if isinstance(b, dict) else None for a, b in d.items()]
    )
    return [i for b in val for i in b]


@_exclude_from_cli
def min_hash_value_by_value(x):
    """Given a dict, return the value paired with the smallest value.

    Args:
        x (dict): Dictionary to inspect.

    Returns:
        any: The value paired with the smallest value in `x`, or None if `x` is empty.
    """
    return next(
        iter(list({k: v for k, v in sorted(x.items(), key=lambda item: item[1])}.values())),
        None,
    )


@_exclude_from_cli
def min_hash_value_by_key(x):
    """Given a dict, return the value paired with the smallest key.

    Args:
        x (dict): Dictionary to inspect.

    Returns:
        any: The value paired with the smallest key in `x`, or None if `x` is empty.
    """
    return next(
        iter(list({k: v for k, v in sorted(x.items(), key=lambda item: item[0])}.values())),
        None,
    )


@_exclude_from_cli
def max_hash_value_by_value(x):
    """Given a dict, return the value paired with the largest value.

    Args:
        x (dict): Dictionary to inspect.

    Returns:
        any: The value paired with the largest value in `x`, or None if `x` is empty.
    """
    try:
        *_, last = iter(list({k: v for k, v in sorted(x.items(), key=lambda item: item[1])}.values()))
    except Exception:
        last = None
    return last


@_exclude_from_cli
def max_hash_value_by_key(x):
    """Given a dict, return the value paired with the largest key.

    Args:
        x (dict): Dictionary to inspect.

    Returns:
        any: The value paired with the largest key in `x`, or None if `x` is empty.
    """
    try:
        *_, last = iter(list({k: v for k, v in sorted(x.items(), key=lambda item: item[0])}.values()))
    except Exception:
        last = None
    return last


@_exclude_from_cli
def flatten(coll):
    """Flatten a collection, but don't split strings.

    Args:
        coll (Iterable): Collection to flatten; may contain nested iterables. Strings are treated as atomic, not iterated.

    Yields:
        any: Each non-iterable (or string) item, in depth-first order.
    """
    for i in coll:
        if isinstance(i, Iterable) and not isinstance(i, str):
            for subc in flatten(i):
                yield subc
        else:
            yield i


@_exclude_from_cli
def get_iterable(x):
    """Treat a scalar or an iterable uniformly.

    Args:
        x (any): A scalar value or an iterable.

    Returns:
        Iterable: `x` itself if it's a non-string iterable, otherwise a one-element tuple containing `x`.
    """
    if isinstance(x, Iterable) and not isinstance(x, str):
        return x
    else:
        return (x,)


@_exclude_from_cli
def remove_falsy(obj):
    """Remove "empty" items from a collection.

    Args:
        obj (dict, list, or any): Structure to clean.

    Returns:
        dict, list, or None: The structure with falsy dict values/list items recursively removed, or None if the result would be entirely empty.
    """
    if isinstance(obj, dict):
        return {k: v for k, v in ((k, remove_falsy(v)) for k, v in obj.items()) if v}
    elif isinstance(obj, list):
        return [v for v in (remove_falsy(i) for i in obj) if v]
    else:
        return obj if obj else None


def load_str_if_json(json_str):
    """Attempt to decode a string as JSON.

    Args:
        json_str (str): String to attempt to parse as JSON.

    Returns:
        any or None: The decoded JSON object, or None if `json_str` isn't valid JSON.
    """
    try:
        return json.loads(json_str)
    except ValueError:
        return None


@_exclude_from_cli
def load_file_if_json(file_handle, attempt_lines=False):
    """Attempt to decode a file (given by handle) as JSON.

    Args:
        file_handle (file-like or None): Open file handle to read JSON from.
        attempt_lines (bool, optional): If whole-file parsing fails, retry treating each line as its own JSON value. Defaults to False.

    Returns:
        any or None: The decoded JSON object (or a list of per-line objects), or None if nothing could be parsed.
    """
    if file_handle is not None:

        try:
            result = json.load(file_handle)
        except ValueError:
            result = None

        if (result is None) and attempt_lines:
            file_handle.seek(0)
            result = []
            for line in file_handle:
                try:
                    result.append(json.loads(line))
                except ValueError:
                    pass
            if not result:
                result = None

    else:
        result = None

    return result


@_exclude_from_cli
def json_obj_serializer(obj):
    """JSON serializer with better support for objects.

    Args:
        obj (any): Arbitrary object to convert.

    Returns:
        any: A JSON-serializable representation of `obj`.
    """
    if isinstance(obj, datetime):
        return obj.astimezone(utc_time_zone).isoformat()

    elif isinstance(obj, GeneratorType):
        return [json_obj_serializer(item) for item in obj]

    elif isinstance(obj, list):
        return [json_obj_serializer(item) for item in obj]

    elif isinstance(obj, dict):
        return {key: json_obj_serializer(value) for key, value in obj.items()}

    elif isinstance(obj, set):
        return {json_obj_serializer(item) for item in obj}

    elif isinstance(obj, tuple):
        return tuple(json_obj_serializer(item) for item in obj)

    elif isinstance(obj, FunctionType):
        return f"function {obj.__name__}" if obj.__name__ != "<lambda>" else "lambda"

    elif isinstance(obj, LambdaType):
        return "lambda"

    elif (not hasattr(obj, "__str__") or obj.__str__ is object.__str__) and (
        not hasattr(obj, "__repr__") or obj.__repr__ is object.__repr__
    ):
        return obj.__class__.__name__

    else:
        return str(obj)
