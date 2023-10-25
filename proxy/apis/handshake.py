from fastapi import APIRouter
from models.models import InitHandshakeBody
import json, hashlib, base64
from cryptoproxies import Cryptoproxy

router = APIRouter()


@router.post("/")
async def handshake(body: InitHandshakeBody):
    with open("config.json", "r") as file:
        config = json.load(file)

    my_crypto_settings = body.crypto_settings.model_dump()
    for type_op in my_crypto_settings.keys():
        for el in my_crypto_settings[type_op].keys():
            if my_crypto_settings[type_op][el] not in config[type_op][el]:
                return {"error": "not valid crypto_settings"}

    file_name = int(hashlib.md5((body.url).encode("utf-8")).hexdigest(), 16)
    file_name = "handshakes/" + str(file_name) + ".json"
    with open(file_name, "w", encoding="utf-8") as file:
        json.dump(body.model_dump(), file)

    cp = Cryptoproxy()
    asym_key = cp.get_asym_public_key(my_crypto_settings)
    base64_bytes = base64.b64encode(asym_key)
    base64_string = base64_bytes.decode("ascii")

    with open("logs.txt", "a") as file:
        log = f"handshake: {body}"
        print(log, file=file)

    return json.dumps({"status": "OK", "asym_key": base64_string})
