"""The passport register circuits too large to bundle in the wallets.

    GET /circuits/<variant>.json.gz

The wallets bundle the circuits a 2^18 proving setup covers (nearly every
passport) and fetch the rest on demand: the compiled circuit (bytecode and
ABI), gzipped, from circuits/ in this repo. Nothing here is trusted: each
wallet pins the sha256 of every circuit in its bundled manifest
(passport_variants.json) and refuses a file that does not hash to it. A
request names its variant, which the registration it is for makes public
anyway (MsgRegister.signature_algorithm).
"""
import os
import re

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "circuits")
_NAME = re.compile(r"lean_poa_[a-z0-9_]{1,64}\.json\.gz")

router = APIRouter()


@router.get("/circuits/{name}")
async def circuit(name: str) -> FileResponse:
    if not _NAME.fullmatch(name):
        raise HTTPException(404, "no such circuit")
    path = os.path.join(DIR, name)
    if not os.path.isfile(path):
        raise HTTPException(404, "no such circuit")
    # Already gzip: the wallet inflates it and checks the hash itself. The
    # explicit identity encoding keeps GZipMiddleware from compressing it again.
    return FileResponse(path, media_type="application/gzip", headers={
        "Content-Encoding": "identity",
        "Cache-Control": "public, max-age=31536000, immutable",
    })
