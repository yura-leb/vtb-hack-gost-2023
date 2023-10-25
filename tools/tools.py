import json, aiohttp, base64
import os, sys, hashlib
from fastapi import HTTPException


def str_to_bytes(s):
    return bytes(s, "utf-8")


def bytes_to_str(s):
    return s.decode("ascii")


def base64_decoding(data_base64: str) -> bytes:
    data_base64_byte = data_base64.encode("ascii")
    return base64.b64decode(data_base64_byte)


def bytes_to_b64_string(s):
    s = base64.b64encode(s)
    return s.decode("ascii")


def open_handshake_by_url(path_dir, url):
    file_name = (
        f"{path_dir}/{str(int(hashlib.md5(url.encode('utf-8')).hexdigest(), 16))}.json"
    )

    if not (os.path.isfile(file_name)):
        return 404

    with open(file_name) as file:
        f = json.load(file)
        return f


def check_pin(cp, body):
    pin_enc_bytes = base64_decoding(body.pin_enc)

    res = open_handshake_by_url("../proxy/handshakes", body.url_sender)
    if res == 404:
        raise HTTPException(status_code=404, detail="handshake was not done")
    else:
        if res["url"] != body.url_sender:
            raise HTTPException(status_code=422, detail="no this url")
    pin = bytes(cp.asym_decrypt(pin_enc_bytes, res["crypto_settings"]["asym"]))
    return cp.verify_password(pin)


import os
import glob


def delete_files_from_dir(path):
    files = glob.glob(path)
    for f in files:
        os.remove(f)
    with open(path[:-1] + "blank", "w") as file:
        pass
