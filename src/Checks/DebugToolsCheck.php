<?php

namespace StackShield\Scanner\Checks;

use Barryvdh\Debugbar\ServiceProvider;
use Clockwork\Support\Laravel\ClockworkServiceProvider;
use StackShield\Scanner\Probes\ScanContext;
use StackShield\Scanner\Results\CheckResult;

/**
 * Debugbar and Clockwork: powerful debug tooling that should not run outside
 * local. Same shape as the Telescope check: installed plus enabled config.
 */
class DebugToolsCheck extends AbstractCheck
{
    public function slug(): string
    {
        return 'debug_tools';
    }

    public function techniques(): array
    {
        return ['registry', 'config'];
    }

    public function run(ScanContext $ctx): CheckResult
    {
        $active = [];

        if ($ctx->classExists(ServiceProvider::class) && (bool) $ctx->config('debugbar.enabled', $ctx->config('app.debug'))) {
            $active[] = 'Debugbar';
        }
        if ($ctx->classExists(ClockworkServiceProvider::class) && (bool) $ctx->config('clockwork.enable', $ctx->config('app.debug'))) {
            $active[] = 'Clockwork';
        }

        if (empty($active)) {
            return CheckResult::pass($this->slug(), 'No debug tooling is active.');
        }

        $names = implode(' and ', $active);
        $severity = $ctx->severityInProduction('high');
        if ($severity === null) {
            return CheckResult::pass($this->slug(), "{$names} active, which is expected in the {$ctx->environment()} environment.", ['active' => $active]);
        }

        return CheckResult::fail($this->slug(), $severity,
            "{$names} active in the {$ctx->environment()} environment. Debug tooling exposes queries, config, and requests.",
            ['active' => $active, 'environment' => $ctx->environment()]);
    }
}
