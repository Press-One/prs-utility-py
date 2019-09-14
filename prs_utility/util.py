from collections import OrderedDict
from urllib.parse import urlencode, quote
from typing import Any, Dict, Union, List


def buf_to_hex(buf: bytes) -> str:
    return buf.hex()


def hex_to_buf(s_hex: str) -> bytes:
    return bytes.fromhex(s_hex)


def dump_buf(buf: bytes, dump: bool = True) -> Union[bytes, str]:
    return buf_to_hex(buf) if dump else buf


def quote_qs(
        string: str,
        safe: str = '',
        encoding: str = 'utf-8',
        errors: str = 'strict'
) -> str:
    return quote(string, safe=safe, encoding=encoding, errors=errors)


def sort_dict(item: dict) -> Dict[str, Any]:
    """
    Sort nested dict

    Input: {"b": 1, "a": {"c": 1,"b": 2}, "c": "c_st[ring]"}
    Output: OrderedDict([
        ('a', OrderedDict([('b', 2), ('c', 1)])),
        ('b', 1),
        ('c', 'c_st[ring]')
    ])
    """
    return OrderedDict(
        (k, sort_dict(v) if isinstance(v, dict) else v)
        for k, v in sorted(item.items())
    )


def flatten_dict(data: Dict[str, Any], parent_key='') -> Dict[str, str]:
    """
    flatten dict

    input: OrderedDict([
        ('a', OrderedDict([('b', 2), ('c', 1)])),
        ('b', 1),
        ('c', 'c_st[ring]')
    ])
    output: OrderedDict([
        ('a[b]', 2),
        ('a[c]', 1),
        ('b', 1),
        ('c', 'c_st[ring]')
    ])
    """
    lst: List = []
    for k, v in data.items():
        new_key = f'{parent_key}[{k}]' if parent_key else k
        if isinstance(v, dict):
            lst.extend(flatten_dict(v, new_key).items())
        else:
            lst.append((new_key, v))
    return OrderedDict(lst)


def get_sorted_qs(data: Dict[str, Any]) -> str:
    """
    flatten sorted quote string

    input: {
        'b': 1, 'a': {'c': 1, 'b': 2}, 'c': 'c_st[ring]',
        'd': {'e': {'f': {'g': 'G'}}}
    }
    output:
        'a%5Bb%5D=2&a%5Bc%5D=1&b=1&c=c_st%5Bring%5D&d%5Be%5D%5Bf%5D%5Bg%5D=G'
    """
    flatten_sorted_data = flatten_dict(sort_dict(data))
    # replace True => true, False => false
    for k, v in flatten_sorted_data.items():
        if v is True:
            flatten_sorted_data[k] = 'true'
        elif v is False:
            flatten_sorted_data[k] = 'false'
    return urlencode(flatten_sorted_data, quote_via=quote_qs)


def remove_prefix_0x(s: str) -> str:
    """remove prefix '0x' or '0X' from string s

    :param s: str

    :return: str, the substring which remove the prefix '0x' or '0X'
    """
    if s[:2].lower() == '0x':
        s = s[2:]
    return s
