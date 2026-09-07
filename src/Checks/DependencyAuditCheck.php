<?php

namespace StackShield\Scanner\Checks;

use StackShield\Scanner\Dependencies\LockFileAuditor;
use StackShield\Scanner\Dependencies\PackagistAdvisoryClient;
use StackShield\Scanner\Probes\ScanContext;
use StackShield\Scanner\Results\CheckResult;

/**
 * Installed dependencies with known advisories, from composer.lock. This talks to
 * Packagist (not StackShield) and is skipped with --offline.
 */
class DependencyAuditCheck extends AbstractCheck
{
    public function __construct(
        protected ?LockFileAuditor $auditor = null,
    ) {}

    public function slug(): string
    {
        return 'dependency_audit';
    }

    public function techniques(): array
    {
        return ['static'];
    }

    public function needsNetwork(): bool
    {
        return true;
    }

    public function run(ScanContext $ctx): CheckResult
    {
        if ($ctx->isOffline()) {
            return CheckResult::notApplicable($this->slug(), 'Skipped in offline mode (the dependency audit queries Packagist).');
        }

        $lock = $ctx->readFile('composer.lock');
        if ($lock === null) {
            return CheckResult::notApplicable($this->slug(), 'No composer.lock found at the project root.');
        }

        $auditor = $this->auditor ?? new LockFileAuditor(new PackagistAdvisoryClient);
        $matches = $auditor->audit($lock);

        if (empty($matches)) {
            return CheckResult::pass($this->slug(), 'No installed dependencies have known advisories.');
        }

        $worst = 'low';
        foreach ($matches as $m) {
            if ($this->rank($m['severity']) > $this->rank($worst)) {
                $worst = $m['severity'] ?? 'medium';
            }
        }

        return CheckResult::fail($this->slug(), $worst ?: 'medium',
            count($matches).' dependency advisory match(es) found.',
            ['matches' => $matches]);
    }

    protected function rank(?string $severity): int
    {
        return ['critical' => 4, 'high' => 3, 'medium' => 2, 'low' => 1][$severity] ?? 2;
    }
}
