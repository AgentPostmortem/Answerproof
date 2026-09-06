"""Optional FastAPI verifier service.

The service is a thin, stateless front end over :func:`verify_receipt`. It lets
a third party POST a receipt (and optionally the original source contents) and
get back a structured verdict, or fetch a small HTML verification page.

Import is guarded so the core library never hard-depends on FastAPI. Install
the extra with ``pip install answerproof[api]``.
"""

from __future__ import annotations

import html
from typing import Any

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import HTMLResponse
    from pydantic import BaseModel
except ModuleNotFoundError as exc:  # pragma: no cover - exercised only without extra
    raise ModuleNotFoundError(
        "The API service requires the 'api' extra: pip install answerproof[api]"
    ) from exc

from . import __version__
from .schema import Receipt
from .verifier import verify_receipt


class VerifyRequest(BaseModel):
    receipt: dict[str, Any]
    source_contents: dict[str, str] | None = None
    expected_public_key: str | None = None


def create_app() -> FastAPI:
    app = FastAPI(
        title="answerproof verifier",
        version=__version__,
        description="Independent verification of answerproof receipts.",
    )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.post("/verify")
    def verify(req: VerifyRequest) -> dict[str, Any]:
        try:
            receipt = Receipt.model_validate(req.receipt)
        except Exception as exc:  # invalid receipt shape
            raise HTTPException(status_code=422, detail=f"invalid receipt: {exc}") from exc
        verdict = verify_receipt(
            receipt,
            source_contents=req.source_contents,
            expected_public_key=req.expected_public_key,
        )
        return verdict.to_dict()

    @app.post("/verify/page", response_class=HTMLResponse)
    def verify_page(req: VerifyRequest) -> str:
        try:
            receipt = Receipt.model_validate(req.receipt)
        except Exception as exc:
            raise HTTPException(status_code=422, detail=f"invalid receipt: {exc}") from exc
        verdict = verify_receipt(
            receipt,
            source_contents=req.source_contents,
            expected_public_key=req.expected_public_key,
        )
        return _render_page(receipt, verdict)

    return app


def _render_page(receipt: Receipt, verdict) -> str:
    p = receipt.payload
    color = "#137333" if verdict.valid else "#c5221f"
    status = "VALID" if verdict.valid else "INVALID"
    rows = "".join(
        f"<tr><td>{'ok' if c.passed else 'FAIL'}</td><td>{html.escape(str(c.name))}</td>"
        f"<td>{html.escape(str(c.detail or ''))}</td></tr>"
        for c in verdict.checks
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>answerproof receipt {html.escape(p.receipt_id)}</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:760px;margin:2rem auto;padding:0 1rem}}
.badge{{display:inline-block;padding:.3rem .8rem;border-radius:6px;color:#fff}}
.badge{{background:{color};font-weight:600}}
table{{border-collapse:collapse;width:100%;margin-top:1rem}}
td,th{{border:1px solid #dadce0;padding:.4rem .6rem;text-align:left;font-size:.9rem}}
code{{background:#f1f3f4;padding:.1rem .3rem;border-radius:4px;word-break:break-all}}
</style></head><body>
<h1>answerproof receipt</h1>
<p class="badge">{status}</p>
<p><strong>Receipt:</strong> <code>{html.escape(p.receipt_id)}</code></p>
<p><strong>Query:</strong> {html.escape(p.query)}</p>
<p><strong>Answer:</strong> {html.escape(p.answer)}</p>
<p><strong>Signer:</strong> <code>{html.escape(receipt.signature.public_key)}</code></p>
<p><strong>Merkle root:</strong> <code>{html.escape(p.merkle_root)}</code></p>
<p><strong>Grounding score:</strong> {html.escape(str(p.grounding.grounding_score))}</p>
<table><thead><tr><th>result</th><th>check</th><th>detail</th></tr></thead>
<tbody>{rows}</tbody></table>
</body></html>"""


# Convenience module-level app for ``uvicorn answerproof.api:app``.
app = create_app()
