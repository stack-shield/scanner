<?php

namespace StackShield\Scanner\Checks;

use StackShield\Scanner\Probes\ScanContext;
use StackShield\Scanner\Results\CheckResult;

class HttpsPostureCheck extends AbstractCheck
{
    public function slug(): string
    {
        return 'https_posture';
    }

    public function run(ScanContext $ctx): CheckResult
    {
        if (! $ctx->isProductionLike()) {
            return CheckResult::notApplicable($this->slug(), "HTTPS posture is only meaningful in production; evaluated in {$ctx->environment()}.");
        }

        $problems = [];

        if (! (bool) $ctx->config('session.secure', false)) {
            $problems[] = 'Session cookies are not marked Secure (session.secure is false).';
        }

        $appUrl = (string) $ctx->config('app.url', '');
        if ($appUrl !== '' && str_starts_with($appUrl, 'http://')) {
            $problems[] = 'APP_URL uses http rather than https.';
        }

        if (empty($problems)) {
            return CheckResult::pass($this->slug(), 'HTTPS posture looks correct for production.');
        }

        return CheckResult::fail($this->slug(), 'medium',
            'HTTPS posture needs attention: '.implode(' ', $problems), ['problems' => $problems]);
    }
}
