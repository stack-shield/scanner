# Contributing

Thanks for helping improve StackShield Scanner.

## Ground rules

- **No phone-home.** The package must never make a network call to StackShield
  without a token. No anonymous telemetry, ever. `tests/NoNetworkWithoutTokenTest`
  guards this; do not weaken it.
- **Checks never crash the run.** Return `not_applicable` on any unexpected
  condition.
- **Original code only.** Ideas from other scanners (Enlightn, and others) are
  fair inspiration, but do not copy, port, or derive their code.

## Adding a check

See `docs/writing-checks.md`. In short: add a class in `src/Checks/`, register it
in `src/CheckRegistry.php`, and add a test.

## Development

```
composer install
vendor/bin/phpunit
vendor/bin/pint
```

## Pull requests

- One check or one concern per PR where possible.
- Include a test.
- Keep result copy plain and direct: no marketing language, no em-dashes.
