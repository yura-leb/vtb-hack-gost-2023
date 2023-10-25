from fastapi import APIRouter, HTTPException
from models.models import Credentials
import json, aiohttp, base64, sys, os

from BaseCryptoSystem import BaseCryptoSystem

sys.path.append(os.path.abspath("../tools/"))
from tools import (
    str_to_bytes,
    open_handshake_by_url,
    bytes_to_b64_string,
    base64_decoding,
)

url = "https://auth.bankingapi.ru/auth/realms/kubernetes/protocol/openid-connect/token"

router = APIRouter()


@router.post("/")
async def go_to_auth(my_url: str, url_proxy: str, credentials: Credentials):
    bcs = BaseCryptoSystem()

    data_Authorization = base64.b64encode(
        bytes(f"{credentials.username}:{credentials.password}", encoding="utf-8")
    )
    data_Authorization = "Basic " + str(data_Authorization.decode("UTF-8"))

    data_Authorization_bytes = str_to_bytes(data_Authorization)

    res = open_handshake_by_url("../fintech_app/handshakes", url_proxy)
    if res == 404:
        raise HTTPException(status_code=404, detail="handshake was not done")
    else:
        if res["url"] != url_proxy:
            raise HTTPException(status_code=422, detail="no this url")
    asym_key_bytes = base64_decoding(res["asym_key"])

    data_Authorization_enc = bytes_to_b64_string(
        bcs.asym_encrypt(
            data_Authorization_bytes, asym_key_bytes, res["crypto_settings"]["asym"]
        )
    )

    url = url_proxy + "proxy_auth"
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    body = {
        "Authorization": data_Authorization_enc,
        "grant_type": "client_credentials",
        "url_sender": my_url,
    }
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

    data, res = bcs.decrypt_check(
        encrypted_data, encrypted_sk, pk_sig, digital_sig, metadata, iv
    )

    if res == False:
        return -1

    access_token = json.loads(data.decode("utf-8"))["access_token"]
    with open("access_token.txt", "w", encoding="utf-8") as file:
        print(access_token, file=file)

    return access_token
