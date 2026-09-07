<?php

namespace StackShield\Scanner\Checks;

use StackShield\Scanner\Probes\ScanContext;
use StackShield\Scanner\Results\CheckResult;

class DebugModeCheck extends AbstractCheck
{
    public function slug(): string
    {
        return 'laravel_debug_mode';
    }

    public function run(ScanContext $ctx): CheckResult
    {
        $debug = (bool) $ctx->config('app.debug');
        $env = $ctx->environment();

        if (! $debug) {
            return CheckResult::pass($this->slug(), "Debug mode is off in the {$env} environment.");
        }

        // Debug on is critical in production/staging, expected (informational) in dev.
        $severity = $ctx->severityInProduction('critical');
        if ($severity === null) {
            return CheckResult::pass($this->slug(), "Debug mode is on, which is expected in the {$env} environment.", ['environment' => $env]);
        }

        return CheckResult::fail($this->slug(), $severity,
            "Debug mode is on in the {$env} environment. Error pages leak configuration and stack traces.",
            ['environment' => $env, 'app_debug' => true]);
    }
}
