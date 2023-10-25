from fastapi import APIRouter, HTTPException
from models.models import AuthBody
import json, aiohttp, base64, sys, os

from cryptoproxies import Cryptoproxy

sys.path.append(os.path.abspath("../tools/"))
from tools import base64_decoding, open_handshake_by_url, bytes_to_str, str_to_bytes

url = "https://auth.bankingapi.ru/auth/realms/kubernetes/protocol/openid-connect/token"

router = APIRouter()


@router.post("/")
async def proxy_auth(auth_body: AuthBody):
    cp = Cryptoproxy()
    enc_credentials_bytes = base64_decoding(auth_body.Authorization)

    res = open_handshake_by_url("../proxy/handshakes", auth_body.url_sender)
    if res == 404:
        raise HTTPException(status_code=404, detail="handshake was not done")
    else:
        if res["url"] != auth_body.url_sender:
            raise HTTPException(status_code=422, detail="no this url")
    credentials = bytes_to_str(
        bytes(cp.asym_decrypt(enc_credentials_bytes, res["crypto_settings"]["asym"]))
    )

    headers = {
        "Authorization": credentials,
        "Content-Type": "application/x-www-form-urlencoded",
    }

    payload = f"grant_type={auth_body.grant_type}"

    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=headers, data=payload) as resp:
            response = await resp.json()

    data = bytearray(str_to_bytes(json.dumps(response)))
    asym_key = base64_decoding(res["asym_key"])
    data, e_key, signature, iv = cp.encrypt_all(data, asym_key, res["crypto_settings"])

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
        log = f"proxy_auth: {auth_body}"
        print(log, file=file)

    return package
