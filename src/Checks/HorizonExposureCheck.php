<?php

namespace StackShield\Scanner\Checks;

use Laravel\Horizon\Horizon;
use StackShield\Scanner\Probes\ScanContext;
use StackShield\Scanner\Results\CheckResult;

class HorizonExposureCheck extends AbstractCheck
{
    public function slug(): string
    {
        return 'horizon_exposure';
    }

    public function techniques(): array
    {
        return ['registry', 'config'];
    }

    public function run(ScanContext $ctx): CheckResult
    {
        if (! $ctx->classExists(Horizon::class)) {
            return CheckResult::notApplicable($this->slug(), 'Laravel Horizon is not installed.');
        }

        if ($ctx->gateExists('viewHorizon')) {
            return CheckResult::pass($this->slug(), 'Horizon is installed and protected by a viewHorizon gate.');
        }

        $severity = $ctx->severityInProduction('high') ?? 'low';

        return CheckResult::fail($this->slug(), $severity,
            "Horizon is installed without a viewHorizon gate in the {$ctx->environment()} environment.",
            ['gated' => false, 'environment' => $ctx->environment()]);
    }
}
