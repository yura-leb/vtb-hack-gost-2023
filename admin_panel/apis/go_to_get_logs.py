from fastapi import APIRouter, Request, HTTPException
from models.models import CryptoSettings
import sys, os, json, base64, aiohttp, hashlib
from typing_extensions import Literal

from BaseCryptoSystem import BaseCryptoSystem

sys.path.append(os.path.abspath("../tools/"))
from tools import (
    str_to_bytes,
    open_handshake_by_url,
    bytes_to_b64_string,
    base64_decoding,
)

router = APIRouter()


@router.post("/")
async def go_to_get_logs(my_url: str, go_to_url: str, pin: str):
    bcs = BaseCryptoSystem()
    pin_bytes = str_to_bytes(pin)

    res = open_handshake_by_url("../admin_panel/handshakes", go_to_url)
    if res == 404:
        raise HTTPException(status_code=404, detail="handshake was not done")
    else:
        if res["url"] != go_to_url:
            raise HTTPException(status_code=422, detail="no this url")
    asym_key_bytes = base64_decoding(res["asym_key"])

    pin_enc = bytes_to_b64_string(
        bcs.asym_encrypt(pin_bytes, asym_key_bytes, res["crypto_settings"]["asym"])
    )

    url = go_to_url + "get_logs"
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    body = {"pin_enc": pin_enc, "url_sender": my_url}
    body = json.dumps(body)

    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=headers, data=body) as resp:
            response = await resp.json()

    print(response)
    encrypted_data = base64_decoding(response["encrypted_data"])
    encrypted_sk = base64_decoding(response["encrypted_sk"])
    pk_sig = base64_decoding(response["pk_sig"])
    digital_sig = base64_decoding(response["digital_sig"])
    iv = base64_decoding(response["iv"])
    metadata = response["metadata"]

    data, res = bcs.decrypt_check(
        encrypted_data, encrypted_sk, pk_sig, digital_sig, metadata, iv
    )

    if res == False:
        return -1

    return json.loads(data.decode("utf-8"))
