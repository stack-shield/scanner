<?php

namespace StackShield\Scanner\Checks;

use StackShield\Scanner\Probes\ScanContext;
use StackShield\Scanner\Results\CheckResult;

class CookieEncryptionCheck extends AbstractCheck
{
    protected const CANDIDATES = [
        'App\\Http\\Middleware\\EncryptCookies',
        'Illuminate\\Cookie\\Middleware\\EncryptCookies',
    ];

    public function slug(): string
    {
        return 'cookie_encryption';
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
            return CheckResult::pass($this->slug(), 'Cookie encryption middleware is present in the web middleware group.');
        }

        return CheckResult::fail($this->slug(), 'medium',
            'No cookie encryption middleware found in the web middleware group.');
    }
}
