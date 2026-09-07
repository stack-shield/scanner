<?php

namespace StackShield\Scanner\Checks;

use Laravel\Telescope\Telescope;
use StackShield\Scanner\Probes\ScanContext;
use StackShield\Scanner\Results\CheckResult;

class TelescopeExposureCheck extends AbstractCheck
{
    public function slug(): string
    {
        return 'telescope_exposure';
    }

    public function techniques(): array
    {
        return ['registry', 'config'];
    }

    public function run(ScanContext $ctx): CheckResult
    {
        if (! $ctx->classExists(Telescope::class)) {
            return CheckResult::notApplicable($this->slug(), 'Laravel Telescope is not installed.');
        }

        $enabled = (bool) $ctx->config('telescope.enabled', true);
        $gated = $ctx->gateExists('viewTelescope');

        if (! $enabled) {
            return CheckResult::pass($this->slug(), 'Telescope is installed but disabled.');
        }
        if ($gated) {
            return CheckResult::pass($this->slug(), 'Telescope is enabled and protected by a viewTelescope gate.');
        }

        $severity = $ctx->severityInProduction('critical') ?? 'low';

        return CheckResult::fail($this->slug(), $severity,
            "Telescope is enabled without a viewTelescope gate in the {$ctx->environment()} environment.",
            ['enabled' => true, 'gated' => false, 'environment' => $ctx->environment()]);
    }
}
