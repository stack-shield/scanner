<?php

namespace StackShield\Scanner\Checks;

use Spatie\LaravelIgnition\IgnitionServiceProvider;
use StackShield\Scanner\Probes\ScanContext;
use StackShield\Scanner\Results\CheckResult;

class IgnitionExposureCheck extends AbstractCheck
{
    public function slug(): string
    {
        return 'ignition_exposure';
    }

    public function techniques(): array
    {
        return ['config', 'registry'];
    }

    public function run(ScanContext $ctx): CheckResult
    {
        $installed = $ctx->classExists(IgnitionServiceProvider::class)
            || $ctx->classExists(\Facade\Ignition\IgnitionServiceProvider::class);

        if (! $installed) {
            return CheckResult::notApplicable($this->slug(), 'Ignition is not installed.');
        }

        // Ignition renders its interactive error page only when debug is on.
        if (! (bool) $ctx->config('app.debug')) {
            return CheckResult::pass($this->slug(), 'Ignition is installed but debug mode is off, so its error page is not shown.');
        }

        $severity = $ctx->severityInProduction('critical');
        if ($severity === null) {
            return CheckResult::pass($this->slug(), "Ignition is active with debug on, which is expected in the {$ctx->environment()} environment.");
        }

        return CheckResult::fail($this->slug(), $severity,
            "Ignition's interactive error page is active in the {$ctx->environment()} environment.",
            ['environment' => $ctx->environment()]);
    }
}
