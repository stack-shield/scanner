<?php

namespace StackShield\Scanner\Dependencies;

use Composer\Semver\Semver;

/**
 * Audits a composer.lock against Packagist advisories: a parse, a lookup, and a
 * version comparison. No composer binary, no process execution.
 */
class LockFileAuditor
{
    public function __construct(
        protected PackagistAdvisoryClient $advisories,
    ) {}

    /**
     * @return array<int, array{package:string, version:string, advisory_id:string, cve:?string, severity:?string, title:string, affected_versions:string, fixed_version:?string, link:?string}>
     */
    public function audit(string $lockJson, bool $includeDev = false): array
    {
        $data = json_decode($lockJson, true);
        if (! is_array($data) || ! isset($data['packages'])) {
            return [];
        }

        $installed = $this->extract($data['packages']);
        if ($includeDev && isset($data['packages-dev'])) {
            $installed = array_merge($installed, $this->extract($data['packages-dev']));
        }

        if (empty($installed)) {
            return [];
        }

        $advisoriesByPackage = $this->advisories->advisoriesFor(array_keys($installed));

        $matches = [];
        foreach ($installed as $name => $version) {
            foreach ($advisoriesByPackage[$name] ?? [] as $advisory) {
                $affected = $advisory['affectedVersions'] ?? '';
                if ($affected === '' || ! $this->satisfies($version, $affected)) {
                    continue;
                }
                $matches[] = [
                    'package' => $name,
                    'version' => $version,
                    'advisory_id' => $advisory['advisoryId'] ?? ($advisory['cve'] ?? 'unknown'),
                    'cve' => $advisory['cve'] ?? null,
                    'severity' => $this->normaliseSeverity($advisory['severity'] ?? null),
                    'title' => $advisory['title'] ?? 'Security advisory',
                    'affected_versions' => $affected,
                    'fixed_version' => $this->fixedVersion($version, $affected),
                    'link' => $advisory['link'] ?? null,
                ];
            }
        }

        return $matches;
    }

    /** @return array<string, string> name => installed version */
    protected function extract(array $packages): array
    {
        $installed = [];
        foreach ($packages as $package) {
            $name = $package['name'] ?? null;
            $version = $package['version'] ?? null;
            if (is_string($name) && is_string($version) && str_contains($name, '/')) {
                $installed[$name] = ltrim($version, 'vV');
            }
        }

        return $installed;
    }

    protected function satisfies(string $version, string $affected): bool
    {
        try {
            return Semver::satisfies($version, $affected);
        } catch (\Throwable) {
            return false;
        }
    }

    /** Only a strict `<X` upper bound names a safe version; `<=X` names none. */
    protected function fixedVersion(string $version, string $affected): ?string
    {
        foreach (explode('|', $affected) as $range) {
            $range = trim($range);
            if ($range === '' || ! $this->satisfies($version, $range)) {
                continue;
            }
            if (preg_match('/<(?!=)\s*([0-9][0-9A-Za-z.\-]*)/', $range, $m)) {
                return $m[1];
            }
        }

        return null;
    }

    protected function normaliseSeverity(?string $severity): ?string
    {
        if ($severity === null) {
            return null;
        }
        $severity = strtolower(trim($severity));

        return in_array($severity, ['critical', 'high', 'medium', 'low'], true) ? $severity : null;
    }
}
