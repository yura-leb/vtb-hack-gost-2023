from fastapi import FastAPI
from apis import go_to_auth, go_to_handshake, go_to_get_data
import uvicorn

import os


app = FastAPI(title="FastAPI for Fintech App")

app.include_router(
    go_to_handshake.router, prefix="/go_to_handshake", tags=["Any information"]
)
app.include_router(go_to_auth.router, prefix="/go_to_auth", tags=["Any information"])
app.include_router(
    go_to_get_data.router, prefix="/go_to_get_data", tags=["Any information"]
)

if __name__ == "__main__":
    uvicorn.run("main:app", port=8000, reload=True)
