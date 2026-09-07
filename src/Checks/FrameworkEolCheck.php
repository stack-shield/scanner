<?php

namespace StackShield\Scanner\Checks;

use StackShield\Scanner\Probes\ScanContext;
use StackShield\Scanner\Results\CheckResult;
use StackShield\Scanner\Support\EolDates;

/**
 * The installed Laravel and running PHP versions against their end-of-life dates.
 */
class FrameworkEolCheck extends AbstractCheck
{
    public function slug(): string
    {
        return 'framework_eol';
    }

    public function techniques(): array
    {
        return ['static', 'config'];
    }

    public function run(ScanContext $ctx): CheckResult
    {
        $problems = [];

        $laravel = $ctx->config('app.version') ? null : $this->laravelVersion($ctx);
        if ($laravel) {
            $eol = EolDates::laravelEolDate($laravel);
            if ($eol && EolDates::isPast($eol)) {
                $problems[] = "Laravel {$laravel} reached end of life on {$eol}.";
            }
        }

        $phpMinor = implode('.', array_slice(explode('.', PHP_VERSION), 0, 2));
        $phpEol = EolDates::PHP[$phpMinor] ?? null;
        if ($phpEol && EolDates::isPast($phpEol)) {
            $problems[] = "PHP {$phpMinor} reached end of security support on {$phpEol}.";
        }

        if (empty($problems)) {
            return CheckResult::pass($this->slug(), 'Laravel and PHP versions are within their supported life.',
                ['laravel' => $laravel, 'php' => $phpMinor]);
        }

        return CheckResult::fail($this->slug(), 'high', implode(' ', $problems),
            ['laravel' => $laravel, 'php' => $phpMinor]);
    }

    protected function laravelVersion(ScanContext $ctx): ?string
    {
        $lock = $ctx->readFile('composer.lock');
        if ($lock === null) {
            return null;
        }
        $data = json_decode($lock, true);
        foreach ($data['packages'] ?? [] as $package) {
            if (($package['name'] ?? null) === 'laravel/framework') {
                return ltrim((string) ($package['version'] ?? ''), 'vV') ?: null;
            }
        }

        return null;
    }
}
