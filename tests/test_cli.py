import json

import pytest

from answerproof.cli import main


def _write_receipt(tmp_path, receipt):
    path = tmp_path / "receipt.json"
    path.write_text(receipt.to_json(), encoding="utf-8")
    return path


def test_keygen_json(capsys):
    rc = main(["keygen"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert "private_key" in out and "public_key" in out


def test_keygen_to_files(tmp_path, capsys):
    out = tmp_path / "id.key"
    rc = main(["keygen", "--out", str(out)])
    assert rc == 0
    assert out.exists()
    assert out.with_suffix(".key.pub").exists()


def test_verify_valid(tmp_path, capsys, receipt):
    path = _write_receipt(tmp_path, receipt)
    rc = main(["verify", str(path)])
    assert rc == 0
    assert "VALID" in capsys.readouterr().out


def test_verify_with_sources_json(tmp_path, capsys, receipt, sources):
    path = _write_receipt(tmp_path, receipt)
    spath = tmp_path / "sources.json"
    spath.write_text(json.dumps(sources), encoding="utf-8")
    rc = main(["verify", str(path), "--sources", str(spath), "--json"])
    assert rc == 0
    verdict = json.loads(capsys.readouterr().out)
    assert verdict["valid"] is True


def test_verify_tampered_returns_nonzero(tmp_path, capsys, receipt):
    d = json.loads(receipt.to_json())
    d["payload"]["answer"] = "tampered"
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(d), encoding="utf-8")
    rc = main(["verify", str(path)])
    assert rc == 1
    assert "INVALID" in capsys.readouterr().out


def test_inspect(tmp_path, capsys, receipt):
    path = _write_receipt(tmp_path, receipt)
    rc = main(["inspect", str(path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert receipt.payload.receipt_id in out
    assert "merkle_root" in out


def test_missing_command_errors():
    with pytest.raises(SystemExit):
        main([])
