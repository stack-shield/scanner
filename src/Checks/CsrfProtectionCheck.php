<?php

namespace StackShield\Scanner\Checks;

use StackShield\Scanner\Probes\ScanContext;
use StackShield\Scanner\Results\CheckResult;

class CsrfProtectionCheck extends AbstractCheck
{
    protected const CANDIDATES = [
        'App\\Http\\Middleware\\VerifyCsrfToken',
        'Illuminate\\Foundation\\Http\\Middleware\\VerifyCsrfToken',
    ];

    public function slug(): string
    {
        return 'csrf_protection';
    }

    public function techniques(): array
    {
        return ['registry'];
    }

    public function run(ScanContext $ctx): CheckResult
    {
        $present = $ctx->groupHasMiddleware('web', self::CANDIDATES);

        if ($present === null) {
            return CheckResult::notApplicable($this->slug(), 'The web middleware group could not be resolved.');
        }
        if ($present) {
            return CheckResult::pass($this->slug(), 'CSRF verification middleware is present in the web middleware group.');
        }

        return CheckResult::fail($this->slug(), 'high',
            'No CSRF verification middleware found in the web middleware group.');
    }
}
