prs-utility 是 PRS 为 Python 提供的算法工具库，包含项目中用到的消息摘要、签名算法。

## Python 版本支持

支持 `>= Python 3.6`

## 安装

```
pip install prs-utility
```

## 使用示例

```python
# 根据 keystore 和 password 得到私钥
import json
import prs_utility

keystore = {
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
password = '123123'
private_key = prs_utility.recover_private_key(
    json.dumps(keystore), password
)
print('private_key:', private_key)

# 计算文件的 hash 值
with open(__file__) as fp:
    content = fp.read()
file_hash = prs_utility.keccak256(content)
print('file hash:', file_hash)

# 根据 PRS 协议组合 block data, 并且使用 privateKey 进行签名
data = {
    'file_hash': file_hash,
}
key_pair = prs_utility.create_key_pair()
private_key = key_pair['privateKey']
sig = prs_utility.sign_block_data(data, private_key)
print('signature:', sig)

# 生成一对新密钥
key_pair = prs_utility.create_key_pair()
print('key_pair:', key_pair)
```

## API

`prs-utility` 提供了常用的加解密函数和一些用于格式转化的工具函数

```
$ pydoc prs_utility
```
