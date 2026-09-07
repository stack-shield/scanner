<?php

namespace StackShield\Scanner\Checks;

use StackShield\Scanner\Probes\ScanContext;
use StackShield\Scanner\Results\CheckResult;

class CorsConfigurationCheck extends AbstractCheck
{
    public function slug(): string
    {
        return 'cors_misconfiguration';
    }

    public function run(ScanContext $ctx): CheckResult
    {
        $origins = (array) $ctx->config('cors.allowed_origins', []);
        $supportsCredentials = (bool) $ctx->config('cors.supports_credentials', false);
        $wildcard = in_array('*', $origins, true);

        if ($wildcard && $supportsCredentials) {
            return CheckResult::fail($this->slug(), 'high',
                'CORS allows any origin (*) while also supporting credentials, which browsers will honour for authenticated cross-origin requests.',
                ['allowed_origins' => $origins, 'supports_credentials' => true]);
        }

        if ($wildcard) {
            return CheckResult::warning($this->slug(),
                'CORS allows any origin (*). This is acceptable for public APIs but review whether it is intended.');
        }

        return CheckResult::pass($this->slug(), 'CORS origins are restricted.');
    }
}
