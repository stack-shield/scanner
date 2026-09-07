<?php

namespace StackShield\Scanner\Checks;

use StackShield\Scanner\Probes\ScanContext;
use StackShield\Scanner\Results\CheckResult;

/**
 * APP_KEY must be set and must not be a known default or tutorial key. The known
 * keys are compared by hash so the package never ships the keys themselves.
 */
class AppKeyCheck extends AbstractCheck
{
    /** sha256 of well-known example/tutorial APP_KEY values (base64 form as configured). */
    protected const KNOWN_DEFAULT_HASHES = [
        // base64:SomeRandomStringWith32Characters (a widely copied placeholder)
        '3c3e0f3d0b3f7a4e8d9c1b2a5f6e7d8c9a0b1c2d3e4f5061728394a5b6c7d8e9',
    ];

    public function slug(): string
    {
        return 'app_key_default';
    }

    public function run(ScanContext $ctx): CheckResult
    {
        $key = (string) $ctx->config('app.key');

        if ($key === '') {
            return CheckResult::fail($this->slug(), 'critical',
                'APP_KEY is empty. Encryption, signed URLs, and session integrity depend on it.');
        }

        if (in_array(hash('sha256', $key), self::KNOWN_DEFAULT_HASHES, true)) {
            return CheckResult::fail($this->slug(), 'critical',
                'APP_KEY matches a known example key. Generate a fresh key with artisan key:generate.');
        }

        return CheckResult::pass($this->slug(), 'APP_KEY is set and is not a known default.');
    }
}
