<?php

namespace StackShield\Scanner\Checks;

use StackShield\Scanner\Probes\ScanContext;
use StackShield\Scanner\Results\CheckResult;

class SessionStorageCheck extends AbstractCheck
{
    public function slug(): string
    {
        return 'session_storage';
    }

    public function run(ScanContext $ctx): CheckResult
    {
        $driver = (string) $ctx->config('session.driver', 'file');
        $encrypt = (bool) $ctx->config('session.encrypt', false);

        // The cookie driver stores session data client side; unencrypted, it is
        // readable and tamperable by the client.
        if ($driver === 'cookie' && ! $encrypt) {
            return CheckResult::fail($this->slug(), 'medium',
                'The session driver is "cookie" without session encryption, so session data is stored unencrypted in the client.',
                ['driver' => $driver, 'encrypt' => false]);
        }

        if (! $encrypt) {
            return CheckResult::warning($this->slug(),
                "Session encryption is off (driver: {$driver}). Consider enabling session.encrypt for defence in depth.",
                ['driver' => $driver, 'encrypt' => false]);
        }

        return CheckResult::pass($this->slug(), "Session storage is sound (driver: {$driver}, encrypted).");
    }
}
