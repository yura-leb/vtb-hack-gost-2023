from http import client
from re import L
from pydantic import BaseModel
from typing_extensions import Literal
from typing import List, Optional, Union


class SymModel(BaseModel):
    type: Literal["kuznechik", "magma", "aes"]
    mode: Literal["CTR", "CBC", "CFB", "ECB", "OFB"]
    pad_mode: Literal["PAD_MODE_1", "PAD_MODE_2"]


class AsymModel(BaseModel):
    hash: Literal[
        "SHA256", "SHA224", "SHA384", "SHA512", "SHA3_224", "SHA3_256", "SHA3_384", "SHA3_512"
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


class ChangeSymModel(BaseModel):
    type: List[Literal["kuznechik", "magma", "aes"]] | Literal[
        "kuznechik", "magma", "aes"
    ]
    mode: List[Literal["CTR", "CBC", "CFB", "ECB", "OFB"]] | Literal[
        "CTR", "CBC", "CFB", "ECB", "OFB"
    ]
    pad_mode: List[Literal["PAD_MODE_1", "PAD_MODE_2"]] | Literal[
        "PAD_MODE_1", "PAD_MODE_2"
    ]


class ChangeAsymModel(BaseModel):
    hash: List[
        Literal[
            "SHA256", "SHA224", "SHA384", "SHA512", "SHA3_224", "SHA3_256", "SHA3_384", "SHA3_512"
        ]
    ] | Literal[
        "SHA256", "SHA224", "SHA384", "SHA512", "SHA3_224", "SHA3_256", "SHA3_384", "SHA3_512"
    ]


class ChangeSignModel(BaseModel):
    type: List[Literal["gost", "rsa"]] | Literal["gost", "rsa"]
    hash: List[
        Literal[
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
    ] | Literal[
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
    param_set: List[Literal["A", "B", "C", "D"]] | Literal["A", "B", "C", "D"]


class ChangeCryptoSettings(BaseModel):
    sym: ChangeSymModel
    asym: ChangeAsymModel
    sign: ChangeSignModel


class InitHandshakeBody(BaseModel):
    asym_key: str
    url: str
    crypto_settings: CryptoSettings


class Package(BaseModel):
    encrypted_data: str
    encrypted_sk: str
    digital_sig: str
    pk_sig: str
    iv: str
    metadata: CryptoSettings


class GetDataBody(BaseModel):
    enc_access_token: Package
    url_recepient: str


class AuthBody(BaseModel):
    Authorization: str
    grant_type: str
    url_sender: str


class AuthAdminBody(BaseModel):
    pin_enc: str
    url_sender: str


class ChangeConfigBody(BaseModel):
    config: ChangeCryptoSettings
    pin_enc: str
    url_sender: str
