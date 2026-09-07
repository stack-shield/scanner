# Writing a check

A check is a small class that inspects the booted application and returns a
`CheckResult`. Checks live in `src/Checks/` and are registered in
`src/CheckRegistry.php`.

## The four probe techniques

Prefer them in this order:

1. **Config introspection** (`$ctx->config('session.secure')`). Reads the booted
   config repository, so it sees what the app actually runs with, including config
   caching and environment overrides. Primary technique for most checks.
2. **Registry introspection** (`$ctx->classExists()`, `$ctx->gateExists()`,
   `$ctx->routes()`, `$ctx->groupHasMiddleware()`). Queries the framework's own
   registries: installed packages, gates, routes, middleware stacks.
3. **Synthetic kernel requests** (`$ctx->syntheticGet('/')`). Dispatches an
   in-memory GET through the full HTTP kernel and inspects the real response.
   Tests behaviour, not configuration. GET/HEAD only, to `/` or a generated
   nonexistent path. Returns null when disabled or on error: degrade to
   config-only, never crash.
4. **Static file analysis** (`$ctx->readFile()`, `$ctx->fileExists()`). Only where
   runtime cannot see the answer, e.g. composer.lock or `.gitignore`.

## Rules

- A check must never throw. Wrap risky probing; return `CheckResult::notApplicable`
  with a reason on any unexpected condition.
- Severity is environment-conditional. Use `$ctx->severityInProduction('critical')`
  so a finding that is expected in local (debug on) is informational there and a
  real severity in production or staging.
- Declare `techniques()` and, if the check needs the network, `needsNetwork()`
  (so `--offline` skips it).
- The `slug()` must match a StackShield catalog slug so results map cleanly when
  reported.

## Skeleton

```php
namespace StackShield\Scanner\Checks;

use StackShield\Scanner\Probes\ScanContext;
use StackShield\Scanner\Results\CheckResult;

class MyCheck extends AbstractCheck
{
    public function slug(): string
    {
        return 'my_catalog_slug';
    }

    public function techniques(): array
    {
        return ['config'];
    }

    public function run(ScanContext $ctx): CheckResult
    {
        if (! $ctx->config('some.setting')) {
            return CheckResult::pass($this->slug(), 'The setting is safe.');
        }

        $severity = $ctx->severityInProduction('high');
        if ($severity === null) {
            return CheckResult::pass($this->slug(), 'Expected in this environment.');
        }

        return CheckResult::fail($this->slug(), $severity, 'The setting is unsafe in production.');
    }
}
```

Register it in `CheckRegistry::all()`, add a test in `tests/`, and open a PR.

## Copy style

Result summaries are plain and direct: no marketing language, no em-dashes or
en-dashes. State what is wrong and, where useful, what to change.
