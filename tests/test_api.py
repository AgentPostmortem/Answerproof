import json

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from answerproof.api import create_app  # noqa: E402


@pytest.fixture
def client():
    return TestClient(create_app())


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_verify_valid_receipt(client, receipt, sources):
    body = {"receipt": json.loads(receipt.to_json()), "source_contents": sources}
    r = client.post("/verify", json=body)
    assert r.status_code == 200
    assert r.json()["valid"] is True


def test_verify_tampered_receipt(client, receipt):
    d = json.loads(receipt.to_json())
    d["payload"]["answer"] = "tampered"
    r = client.post("/verify", json={"receipt": d})
    assert r.status_code == 200
    assert r.json()["valid"] is False


def test_verify_invalid_shape_returns_422(client):
    r = client.post("/verify", json={"receipt": {"not": "a receipt"}})
    assert r.status_code == 422


def test_verify_page_renders_html(client, receipt, sources):
    body = {"receipt": json.loads(receipt.to_json()), "source_contents": sources}
    r = client.post("/verify/page", json=body)
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "VALID" in r.text
