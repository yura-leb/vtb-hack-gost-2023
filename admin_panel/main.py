from fastapi import FastAPI
from apis import go_to_handshake, go_to_change_config, go_to_get_logs
import uvicorn

import os


app = FastAPI(title="FastAPI for Admin")

app.include_router(
    go_to_handshake.router, prefix="/go_to_handshake", tags=["Any information"]
)
app.include_router(
    go_to_get_logs.router, prefix="/go_to_get_logs", tags=["Any information"]
)
app.include_router(
    go_to_change_config.router, prefix="/go_to_change_config", tags=["Any information"]
)

if __name__ == "__main__":
    uvicorn.run("main:app", port=8008, reload=True)
