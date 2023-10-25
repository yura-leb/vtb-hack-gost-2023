from fastapi import APIRouter, HTTPException

import json, aiohttp, base64
import os, sys, hashlib

from BaseCryptoSystem import BaseCryptoSystem

sys.path.append(os.path.abspath("../tools/"))
from tools import (
    str_to_bytes,
    open_handshake_by_url,
    bytes_to_b64_string,
    base64_decoding,
)

router = APIRouter()


def base64_decoding(data_base64: str) -> bytes:
    data_base64_byte = data_base64.encode("ascii")
    return base64.b64decode(data_base64_byte)


@router.post("/")
async def go_to_get_data(my_url: str, url_get_data: str):
    bcs = BaseCryptoSystem()

    url = url_get_data + "proxy_get_data"

    with open("access_token.txt", "r", encoding="utf-8") as file:
        access_token = file.read().strip()

    res = open_handshake_by_url("../fintech_app/handshakes", url_get_data)
    if res == 404:
        raise HTTPException(status_code=404, detail="handshake was not done")
    else:
        if res["url"] != url_get_data:
            raise HTTPException(status_code=422, detail="no this url")

    data = bytearray(str_to_bytes(access_token))
    asym_key = base64_decoding(res["asym_key"])
    data, e_key, signature, iv = bcs.encrypt_all(data, asym_key, res["crypto_settings"])

    pk_sig = bcs.get_sign_public_key(res["crypto_settings"])

    enc_data_base64 = base64.b64encode(data)
    enc_sym_key_base64 = base64.b64encode(e_key)
    sign_base64 = base64.b64encode(signature)
    iv_base64 = base64.b64encode(iv)
    pk_sig_base64 = base64.b64encode(pk_sig)

    package = {
        "encrypted_data": enc_data_base64.decode("ascii"),
        "encrypted_sk": enc_sym_key_base64.decode("ascii"),
        "digital_sig": sign_base64.decode("ascii"),
        "pk_sig": pk_sig_base64.decode("ascii"),
        "iv": iv_base64.decode("ascii"),
        "metadata": res["crypto_settings"],
    }

    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    body = {"enc_access_token": package, "url_recepient": my_url}
    body = json.dumps(body)

    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=headers, data=body) as resp:
            response = await resp.json()

    encrypted_data = base64_decoding(response["encrypted_data"])
    encrypted_sk = base64_decoding(response["encrypted_sk"])
    pk_sig = base64_decoding(response["pk_sig"])
    digital_sig = base64_decoding(response["digital_sig"])
    iv = base64_decoding(response["iv"])
    metadata = response["metadata"]
    print(encrypted_data)
    print("\n")
    data, res = bcs.decrypt_check(
        encrypted_data, encrypted_sk, pk_sig, digital_sig, metadata, iv
    )
    print(data.decode("utf-8"))
    if res == False:
        return -1

    return json.loads(data.decode("utf-8"))
