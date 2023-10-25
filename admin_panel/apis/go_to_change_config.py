from fastapi import APIRouter, Request, HTTPException
from models.models import ChangeCryptoSettings
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
async def go_to_change_config(
    my_url: str, go_to_url: str, pin: str, settings: ChangeCryptoSettings
):
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

    url = go_to_url + "change_config"
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    body = {"config": settings.model_dump(), "pin_enc": pin_enc, "url_sender": my_url}
    print(body)
    body = json.dumps(body)

    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=headers, data=body) as resp:
            response = await resp.json()

    return 0
