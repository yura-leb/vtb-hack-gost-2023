from http import client
from re import L
from pydantic import BaseModel
from typing_extensions import Literal
from typing import List, Optional, Union


class Credentials(BaseModel):
    username: Literal["team019"]
    password: Literal["eXPSIXcBRtcGr5oBAsEsfReDxj678WhH"]


class SymModel(BaseModel):
    type: Literal["kuznechik", "magma", "aes"]
    mode: Literal["CTR", "CBC", "CFB", "ECB", "OFB"]
    pad_mode: Literal["PAD_MODE_1", "PAD_MODE_2"]


class AsymModel(BaseModel):
    hash: Literal[
        "SHA256", "SHA224", "SHA384", "SHA3_224", "SHA512", "SHA3_256", "SHA3_384", "SHA3_512"
    ]


class SignModel(BaseModel):
    type: Literal["gost", "rsa"]
    hash: Literal[
        "streebog256",
        "streebog512",
        "SHA256",
        "SHA224",
        "SHA384",
        "SHA512",
        "SHA3_224",
        "SHA3_256",
        "SHA3_384",
        "SHA3_512",
    ]
    param_set: Literal["A", "B", "C", "D"]


class CryptoSettings(BaseModel):
    sym: SymModel
    asym: AsymModel
    sign: SignModel
