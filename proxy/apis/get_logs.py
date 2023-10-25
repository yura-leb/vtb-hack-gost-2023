from fastapi import APIRouter, Request, HTTPException
from models.models import AuthAdminBody
import sys, os, json, base64, aiohttp, hashlib

from cryptoproxies import Cryptoproxy

sys.path.append(os.path.abspath("../tools/"))
from tools import (
    str_to_bytes,
    open_handshake_by_url,
    bytes_to_b64_string,
    base64_decoding,
    bytes_to_str,
    check_pin,
)

router = APIRouter()


@router.post("/")
async def change_config(body: AuthAdminBody):
    cp = Cryptoproxy()

    if not check_pin(cp, body):
        raise HTTPException(status_code=422, detail="incorrect pin")

    with open("logs.txt", "r") as file:
        dict_of_logs = {"logs": file.readlines()}

    data = str_to_bytes(json.dumps(dict_of_logs))
    res = open_handshake_by_url("../proxy/handshakes", body.url_sender)
    if res == 404:
        raise HTTPException(status_code=404, detail="handshake was not done")
    else:
        if res["url"] != body.url_sender:
            raise HTTPException(status_code=422, detail="no this url")

    asym_key_base64_byte = bytes(res["asym_key"], "utf-8")
    asym_key = base64.b64decode(asym_key_base64_byte)

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
        log = f"get_logs: {body}"
        print(log, file=file)

    return package
