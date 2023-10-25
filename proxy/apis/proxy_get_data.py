from fastapi import APIRouter, HTTPException
import json, hashlib, base64, aiohttp, os, sys
from models.models import GetDataBody

from cryptoproxies import Cryptoproxy

sys.path.append(os.path.abspath("../tools/"))
from tools import open_handshake_by_url, base64_decoding

api_url = "https://hackaton.bankingapi.ru/api/vtbid/v1/oauth2/me"

router = APIRouter()


@router.post("/")
async def proxy_get_data(body: GetDataBody):
    cp = Cryptoproxy()
    package = body.enc_access_token.dict()
    encrypted_data = base64_decoding(package["encrypted_data"])
    encrypted_sk = base64_decoding(package["encrypted_sk"])
    pk_sig = base64_decoding(package["pk_sig"])
    digital_sig = base64_decoding(package["digital_sig"])
    iv = base64_decoding(package["iv"])
    metadata = package["metadata"]

    data, res = cp.decrypt_check(
        encrypted_data, encrypted_sk, pk_sig, digital_sig, metadata, iv
    )

    if res == False:
        return -1
    access_token = data.decode("utf-8")

    payload = {}
    headers = {"Authorization": "Bearer " + access_token}

    async with aiohttp.ClientSession() as session:
        async with session.get(api_url, headers=headers, data=payload) as resp:
            response = await resp.read()

    res = open_handshake_by_url("../proxy/handshakes", body.url_recepient)
    if res == 404:
        raise HTTPException(status_code=404, detail="handshake was not done")
    else:
        if res["url"] != body.url_recepient:
            raise HTTPException(status_code=422, detail="no this url")

    asym_key_base64_byte = bytes(res["asym_key"], "utf-8")
    asym_key = base64.b64decode(asym_key_base64_byte)

    data, e_key, signature, iv = cp.encrypt_all(
        response, asym_key, res["crypto_settings"]
    )
    pk_sig = cp.get_sign_public_key(res["crypto_settings"])

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

    with open("logs.txt", "a") as file:
        log = f"proxy_get_data: {package}"
        print(log, file=file)

    return package
