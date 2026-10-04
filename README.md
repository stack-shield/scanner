# StackShield Scanner

Run Laravel security posture checks locally, from inside your application.

`stackshield/scanner` inspects the live, booted application (config and runtime
state, not parsed files) and reports on the security posture your codebase
controls. It is the inside view. It pairs with StackShield's outside view, the
verified scan of what attackers actually see, but it needs no account and makes
no network calls to StackShield unless you give it a token.

```bash
composer config repositories.stackshield-scanner vcs https://github.com/stack-shield/scanner.git
composer require --dev stackshield/scanner:dev-main
php artisan stackshield:scan
```

The package is available from this public GitHub repository. It is not yet
listed on Packagist, so the VCS repository entry and `dev-main` constraint are
needed for Composer installation until the first package release.

## What this checks

The package reports the inside view: configuration and runtime posture. Checks
map to the StackShield catalog (see `docs/check-catalog` on the SaaS, mirrored by
each check's slug). The current set:

- Debug mode (APP_DEBUG, APP_ENV)
- Session cookie flags (HttpOnly, Secure, SameSite) and session driver/encryption
- Security headers as actually emitted
- Telescope, Horizon, Ignition exposure (installed, enabled, gated)
- Debugbar and Clockwork
- CSRF middleware and its exemption list
- Cookie encryption middleware
- CORS wildcard with credentials
- APP_KEY set and not a known default
- HTTPS posture (secure cookies, APP_URL, in production)
- Rate limiting on auth-shaped routes
- Framework and PHP end-of-life
- Dependency advisory audit (composer.lock vs Packagist)

Every result is labelled the **inside view**: self-reported and unverified.

## What this cannot check

The inside view cannot see what the outside sees. Open ports, TLS at the edge,
DNS and subdomain takeover, publicly reachable files, and headers as they arrive
after proxies and CDNs are the **outside view**, verified by StackShield from
outside your application. Some concerns (debug mode, headers, session cookies,
Telescope) are checkable from both sides, and the two can disagree when
infrastructure overrides your configuration. That is what StackShield's mismatch
detection surfaces.

This package is config and runtime posture. It is not a static code analyser. For
SQL injection patterns, unsafe Blade output, and mass-assignment analysis, use
Psalm taint analysis, PHPStan/Larastan, or semgrep PHP rules alongside it.
[roave/security-advisories](https://github.com/Roave/SecurityAdvisories) is a good
complementary tool that blocks installing known-vulnerable packages in the first
place.

## Environment matters

A local scan in development will and should have `APP_DEBUG=true`; that is not a
finding. Every result records the environment it was evaluated in, and severity is
environment-conditional: debug on is critical in production or staging,
informational in local. The report states the evaluated environment at the top.

For results that reflect production reality, run the command where your production
environment variables are composed, which is your deploy pipeline (see CI below).

## Output and exit codes

```
php artisan stackshield:scan                # human-readable report
php artisan stackshield:scan --format=json  # machine-readable
php artisan stackshield:scan --format=sarif # SARIF 2.1.0 for GitHub code scanning
php artisan stackshield:scan --format=compact
php artisan stackshield:scan --offline      # skip the dependency audit (no network at all)

php artisan stackshield:scan --format=sarif --output=stackshield.sarif
```

`--output` writes the report to a file instead of stdout, which keeps the payload
out of CI logs and gives the SARIF uploader a path to point at.

SARIF reports contain failures and warnings only. Passing and not-applicable
checks are omitted, so a clean run produces a valid report with no findings
rather than annotating every pull request with things that are fine.

The command exits non-zero when a finding at or above the `fail_on` severity is
present (default `critical`; override with `--fail-on=high` or config). This is
your CI gate.

## Reporting to StackShield (optional, off by default)

Nothing is sent to StackShield without a token **and** reporting being active.

- Set a token via `STACKSHIELD_TOKEN` or the published config. Your project API
  key is in the StackShield dashboard.
- Send results with `--report`, or set `reporting.enabled` in config.
- `--no-report` always wins.

```
STACKSHIELD_TOKEN=sk_... php artisan stackshield:scan --report
```

### Exactly what is transmitted, and when

Only when a token is present and reporting is active, the package POSTs to your
configured endpoint:

```json
{
  "package_version": "1.0.0",
  "environment": "production",
  "origin": "local",
  "results": [
    { "slug": "laravel_debug_mode", "status": "pass", "severity": null, "detail": { "summary": "..." } }
  ]
}
```

No source code, no environment variables, no secrets. The token is never logged.
Self-reported results never affect your external security score or badge.

The dependency audit is the only check that uses the network without a token, and
it talks to **Packagist**, not StackShield. Use `--offline` to disable it.

## CI: combined deploy scan

Run the inside checks, submit them, and trigger the outside scan of a URL as one
deploy-scan event:

```
php artisan stackshield:scan --url=https://staging.example.com --report
```

The run exits non-zero if either the inside checks or the outside scan report a
critical finding. Unknown URLs need `--register` in non-interactive mode; a URL
scanned from a codebase pipeline is registered as linked by default (`--standalone`
to override).

### GitHub Actions

The published action runs the scan, uploads SARIF to the Security tab, and fails
the build on findings at or above your threshold:

```yaml
name: security
on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # required for the SARIF upload

jobs:
  stackshield:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: shivammathur/setup-php@v2
        with: { php-version: '8.3' }
      - run: composer install --no-interaction --prefer-dist

      - uses: stack-shield/scanner@v1
        with:
          fail-on: high
```

Findings then appear in the repository's Security tab and as annotations on the
pull request that introduced them.

To combine the inside checks with an external scan of a deployed URL, pass a URL
and a token:

```yaml
      - uses: stack-shield/scanner@v1
        with:
          fail-on: critical
          url: ${{ vars.STAGING_URL }}
          token: ${{ secrets.STACKSHIELD_TOKEN }}
```

Without the action, the raw command works the same way:

```yaml
      - run: php artisan stackshield:scan --url=${{ vars.STAGING_URL }} --report --register
        env:
          STACKSHIELD_TOKEN: ${{ secrets.STACKSHIELD_TOKEN }}
          APP_ENV: production
```

#### Action inputs

| Input | Default | Purpose |
|---|---|---|
| `fail-on` | `critical` | Severity that fails the build |
| `working-directory` | `.` | Directory holding the Laravel app |
| `sarif-file` | `stackshield.sarif` | Where to write the report |
| `upload-sarif` | `true` | Upload to code scanning |
| `url` | none | Also scan this URL from the outside |
| `token` | none | StackShield project token |
| `app-env` | `production` | Environment to evaluate severity against |
| `offline` | `false` | Skip the dependency audit |

The SARIF upload runs even when the scan fails, so the findings that failed the
build still reach the Security tab. The build is failed afterwards.

## Badge

Add your project's status badge from the StackShield dashboard. The badge shows
the verified outside view, never the self-reported inside view.

```markdown
[![StackShield](https://stackshield.io/badge/your-project.svg)](https://stackshield.io/status/your-project)
```

## Configuration

```
php artisan vendor:publish --tag=stackshield-config
```

See `config/stackshield.php` for reporting, skipped checks, the fail severity, and
the `probes.synthetic_requests` flag (synthetic requests boot the full middleware
stack; disable to run affected checks in config-only mode).

## Contributing

Checks are easy to add. See `CONTRIBUTING.md` and `docs/writing-checks.md`.

## License

MIT. See `LICENSE`.

---

The inside view is one half. The outside view, what attackers actually see, is
what StackShield verifies. Run a free external scan at https://stackshield.io.
