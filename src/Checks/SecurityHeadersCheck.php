<?php

namespace StackShield\Scanner\Checks;

use StackShield\Scanner\Probes\ScanContext;
use StackShield\Scanner\Results\CheckResult;

/**
 * Security headers as actually emitted. This uses a synthetic request so it
 * catches middleware that is registered but misconfigured. Without synthetic
 * requests it cannot observe emitted headers and reports not_applicable.
 */
class SecurityHeadersCheck extends AbstractCheck
{
    protected const HEADERS = [
        'Content-Security-Policy' => 'medium',
        'Strict-Transport-Security' => 'medium',
        'X-Frame-Options' => 'medium',
        'X-Content-Type-Options' => 'low',
        'Referrer-Policy' => 'low',
    ];

    public function slug(): string
    {
        return 'security_headers';
    }

    public function techniques(): array
    {
        return ['synthetic'];
    }

    public function run(ScanContext $ctx): CheckResult
    {
        if (! $ctx->syntheticEnabled()) {
            return CheckResult::notApplicable($this->slug(), 'Synthetic requests are disabled, so emitted headers cannot be observed.');
        }

        $response = $ctx->syntheticGet('/');
        if ($response === null) {
            return CheckResult::notApplicable($this->slug(), 'A synthetic request to / could not be completed.');
        }

        $missing = [];
        foreach (self::HEADERS as $header => $severity) {
            if (! $response->headers->has($header)) {
                $missing[] = $header;
            }
        }

        if (empty($missing)) {
            return CheckResult::pass($this->slug(), 'All checked security headers are present on the response.');
        }

        // The worst missing header sets the severity.
        $worst = 'low';
        foreach ($missing as $header) {
            if (self::HEADERS[$header] === 'medium') {
                $worst = 'medium';
            }
        }

        return CheckResult::fail($this->slug(), $worst,
            'Missing security headers on the response: '.implode(', ', $missing).'.',
            ['missing' => $missing]);
    }
}
