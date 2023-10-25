from fastapi import FastAPI

from apis import handshake, proxy_get_data, proxy_auth, change_config, get_logs
import uvicorn
import os, json

app = FastAPI(title="proxy for you API")

app.include_router(handshake.router, prefix="/handshake", tags=["Any information"])
app.include_router(proxy_auth.router, prefix="/proxy_auth", tags=["Any information"])
app.include_router(
    proxy_get_data.router, prefix="/proxy_get_data", tags=["Any information"]
)


app.include_router(
    change_config.router, prefix="/change_config", tags=["Any information"]
)
app.include_router(get_logs.router, prefix="/get_logs", tags=["Any information"])


if __name__ == "__main__":
    with open("config_init.json", "r") as file:
        config = json.load(file)
        with open("config.json", "w") as fp:
            json.dump(config, fp, indent=2)

    uvicorn.run("main:app", port=8080, reload=True)
