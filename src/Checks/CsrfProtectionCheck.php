<?php

namespace StackShield\Scanner\Checks;

use StackShield\Scanner\Probes\ScanContext;
use StackShield\Scanner\Results\CheckResult;

class CsrfProtectionCheck extends AbstractCheck
{
    /**
     * Laravel 10 apps ship their own VerifyCsrfToken, Laravel 11 and 12 register
     * ValidateCsrfToken, and Laravel 13 registers PreventRequestForgery, the class
     * both of the older names now extend. Matching is by is_a, so subclasses count.
     */
    protected const CANDIDATES = [
        'App\\Http\\Middleware\\VerifyCsrfToken',
        'Illuminate\\Foundation\\Http\\Middleware\\VerifyCsrfToken',
        'Illuminate\\Foundation\\Http\\Middleware\\ValidateCsrfToken',
        'Illuminate\\Foundation\\Http\\Middleware\\PreventRequestForgery',
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
