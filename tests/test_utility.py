import json
import pytest

from prs_utility.util import remove_prefix_0x, dump_buf
from prs_utility.core import get_private_key
from prs_utility import (
    keccak256,
    recover_private_key,
    private_key_to_address,
    create_key_pair,
    sign_text,
    sign_block_data,
    sig_to_address,
    sig_to_address_from_block,
)
from prs_utility import hex_to_buf


KEYSTORE = {
    "address": "758ea2601697fbd3ba6eb6774ed70b6c4cdb0ef9",
    "crypto": {
        "cipher": "aes-128-ctr",
        "ciphertext": "92af6f6710eba271eae5ac7fec72c70d9f49215e7880a0c45d4c53e56bd7ea59",
        "cipherparams": {
            "iv": "13ddf95d970e924c97e4dcd29ba96520"
        },
        "mac": "b9d81d78f067334ee922fb2863e32c14cbc46e479eeb0acc11fb31e39256004e",
        "kdf": "pbkdf2",
        "kdfparams": {
            "c": 262144,
            "dklen": 32,
            "prf": "hmac-sha256",
            "salt": "79f90bb603491573e40a79fe356b88d0c7869852e43c2bbaabed44578a82bbfa"
        }
    },
    "id": "93028e51-a2a4-4514-bc1a-94b089445f35",
    "version": 3
}
PASSWORD = '123123'
PRIVATE_KEY = '6e204c62726a19fe3f43c4ca9739b7ffa37e4a3226f824f3e24e00a5890addc6'
ADDRESS = '758ea2601697fbd3ba6eb6774ed70b6c4cdb0ef9'


@pytest.mark.parametrize('s', ['0x123456', '0X123456', '123456'])
def test_remove_prefix_0x(s):
    remove_prefix_0x(s) == '123456'


def test_get_private_key():
    pk = get_private_key(PRIVATE_KEY)
    assert dump_buf(pk.to_bytes(), dump=True) == PRIVATE_KEY

    pk_hex_str = remove_prefix_0x(pk.to_hex())
    pk2 = get_private_key(pk_hex_str)
    assert dump_buf(pk2.to_bytes(), dump=True) == PRIVATE_KEY

    pk3 = get_private_key(pk2)
    assert dump_buf(pk3.to_bytes(), dump=True) == PRIVATE_KEY


@pytest.mark.parametrize('dump', [True, False])
def test_recover_private_key(dump):
    keystore = json.dumps(KEYSTORE)
    private_key = recover_private_key(keystore, PASSWORD, dump)
    if dump:
        assert isinstance(private_key, str)
        assert private_key == PRIVATE_KEY
    else:
        assert isinstance(private_key, bytes)
        assert private_key == hex_to_buf(PRIVATE_KEY)


def test_private_key_to_address():
    address = private_key_to_address(PRIVATE_KEY)
    assert address == ADDRESS


def test_keccak256():
    message = 'hello prs'
    _hash = keccak256(message)
    _HASH = '647df39ad889e83cc0b9b65375672d1bfe282565c564d3d553a435bf80e67d92'
    assert _hash == _HASH


@pytest.mark.parametrize('dump', [True, False])
def test_create_key_pair(dump):
    pair = create_key_pair(dump)
    for item in {'privateKey', 'publicKey', 'address'}:
        assert item in pair
        v = pair[item]
        if item == 'address':
            assert isinstance(v, str)
            assert v[:2].lower() != '0x'
            continue

        if dump:
            assert isinstance(v, str)
            assert v[:2].lower() != '0x'
        else:
            assert isinstance(v, bytes)


def test_sign_text():
    key_pair = create_key_pair()
    private_key = key_pair['privateKey']
    address = key_pair['address']
    message = 'hello, world'
    sig = sign_text(message, private_key)
    _hash, signature = sig['hash'], sig['signature']
    print('hash:', _hash)
    print('signature:', signature)
    recover_addr = sig_to_address(_hash, signature)
    assert address == recover_addr


def test_sign_block_data():
    key_pair = create_key_pair()
    private_key = key_pair['privateKey']
    address = key_pair['address']
    data = {'a': 111, 'b': 222}
    sig = sign_block_data(data, private_key)
    _hash, signature = sig['hash'], sig['signature']
    recover_addr = sig_to_address(_hash, signature)
    assert address == recover_addr


def test_sig_to_address_from_block():
    key_pair = create_key_pair()
    private_key = key_pair['privateKey']
    address = key_pair['address']
    data = {'a': 111, 'b': 222}
    sig = sign_block_data(data, private_key)
    signature = sig['signature']
    recover_addr = sig_to_address_from_block(data, signature)
    assert address == recover_addr
