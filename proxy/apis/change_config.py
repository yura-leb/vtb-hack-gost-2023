from fastapi import APIRouter, Request, HTTPException
from models.models import ChangeConfigBody
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
    delete_files_from_dir,
)

router = APIRouter()


@router.post("/")
async def change_config(body: ChangeConfigBody):
    print(1)
    cp = Cryptoproxy()

    if not check_pin(cp, body):
        raise HTTPException(status_code=422, detail="incorrect pin")
    with open("config.json", "w") as fp:
        json.dump(body.config.model_dump(), fp, indent=2)

    delete_files_from_dir("handshakes/*")

    with open("logs.txt", "a") as file:
        log = f"change_config: {body}"
        print(log, file=file)

    return 0
