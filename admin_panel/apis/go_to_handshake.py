from fastapi import APIRouter, Request
from models.models import CryptoSettings
import sys, os, json, base64, aiohttp, hashlib

from BaseCryptoSystem import BaseCryptoSystem

router = APIRouter()


@router.post("/")
async def go_to_handshake(my_url: str, go_to_url: str, crypto_settings: CryptoSettings):
    bcs = BaseCryptoSystem()
    asym_key = bcs.get_asym_public_key(crypto_settings.model_dump())
    base64_bytes = base64.b64encode(asym_key)
    base64_string = base64_bytes.decode("ascii")

    url = go_to_url + "handshake"

    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    body = {
        "asym_key": base64_string,
        "url": my_url,
        "crypto_settings": crypto_settings.model_dump(),
    }
    body = json.dumps(body)

    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=headers, data=body) as resp:
            response = await resp.json()

    response = json.loads(response)
    if response["status"] == "OK":
        body = {
            "asym_key": response["asym_key"],
            "url": go_to_url,
            "crypto_settings": crypto_settings.dict(),
        }
        file_name = int(hashlib.md5(go_to_url.encode("utf-8")).hexdigest(), 16)
        file_name = "handshakes/" + str(file_name) + ".json"
        with open(file_name, "w", encoding="utf-8") as file:
            json.dump(body, file)

    return f"Succesfull handshake with {go_to_url}"
