<?php

namespace StackShield\Scanner\Checks;

use StackShield\Scanner\Probes\ScanContext;
use StackShield\Scanner\Results\CheckResult;

/**
 * The CSRF exclusion list. Broad wildcards or a large number of exemptions widen
 * the CSRF attack surface. Reads the middleware's excluded paths, which on
 * Laravel 11+ include the static list registered in bootstrap/app.php.
 */
class CsrfExemptionsCheck extends AbstractCheck
{
    protected const CANDIDATES = [
        'App\\Http\\Middleware\\VerifyCsrfToken',
        'Illuminate\\Foundation\\Http\\Middleware\\PreventRequestForgery',
        'Illuminate\\Foundation\\Http\\Middleware\\VerifyCsrfToken',
    ];

    public function techniques(): array
    {
        return ['registry'];
    }

    public function slug(): string
    {
        return 'csrf_exemptions';
    }

    public function run(ScanContext $ctx): CheckResult
    {
        $except = $this->exemptions($ctx);
        if ($except === null) {
            return CheckResult::notApplicable($this->slug(), 'The CSRF exclusion list could not be read.');
        }

        $broad = array_filter($except, fn ($p) => $p === '*' || str_ends_with((string) $p, '/*') || $p === '/*');

        if (! empty($broad)) {
            return CheckResult::fail($this->slug(), 'high',
                'The CSRF exclusion list contains a broad wildcard, disabling CSRF protection for many routes.',
                ['exemptions' => $except]);
        }

        if (count($except) > 10) {
            return CheckResult::warning($this->slug(),
                count($except).' CSRF exemptions are configured. Review whether each is necessary.',
                ['count' => count($except)]);
        }

        return CheckResult::pass($this->slug(), 'The CSRF exclusion list is small and specific.', ['count' => count($except)]);
    }

    protected function exemptions(ScanContext $ctx): ?array
    {
        foreach (self::CANDIDATES as $class) {
            if (! class_exists($class)) {
                continue;
            }
            try {
                $instance = app($class);
                if (method_exists($instance, 'getExcludedPaths')) {
                    return (array) $instance->getExcludedPaths();
                }
                $ref = new \ReflectionClass($instance);
                if (! $ref->hasProperty('except')) {
                    continue;
                }
                $prop = $ref->getProperty('except');
                $prop->setAccessible(true);

                return (array) $prop->getValue($instance);
            } catch (\Throwable) {
                continue;
            }
        }

        return null;
    }
}
