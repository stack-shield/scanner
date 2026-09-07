<?php

namespace StackShield\Scanner\Reporting;

use StackShield\Scanner\Results\CheckResult;

/**
 * Renders results as SARIF 2.1.0, the format GitHub code scanning ingests.
 *
 * Uploading this to github/codeql-action/upload-sarif puts inside-view findings
 * in a repository's Security tab and annotates pull requests, which is why the
 * format is worth carrying beyond plain JSON.
 *
 * A note on locations. SARIF expects a file and line per result, and these checks
 * inspect the booted application rather than parsing source, so there is usually
 * no honest line to point at. Every result is therefore anchored to the file that
 * governs it where one is known (config/session.php for session checks, and so
 * on) and to composer.json otherwise, which is guaranteed to exist in any project
 * running this. Inventing line numbers would be worse than pointing at the file.
 */
class SarifFormatter
{
    private const SCHEMA = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json';

    /** Catalog pages that exist on the SaaS. Others fall back to the index. */
    private const HELP_URIS = [
        'api_rate_limit' => 'api-rate-limiting',
        'cors_misconfiguration' => 'cors-misconfiguration',
        'csrf_protection' => 'csrf-protection',
        'ignition_exposure' => 'ignition-exposure',
        'laravel_debug_mode' => 'laravel-debug-mode',
        'security_headers' => 'security-headers',
        'session_configuration' => 'session-configuration',
        'telescope_exposure' => 'telescope-exposure',
    ];

    /** The file that governs each check, for a defensible SARIF location. */
    private const LOCATIONS = [
        'api_rate_limit' => 'routes/api.php',
        'app_key_default' => 'config/app.php',
        'cookie_encryption' => 'app/Http/Kernel.php',
        'cors_misconfiguration' => 'config/cors.php',
        'csrf_exemptions' => 'app/Http/Middleware/VerifyCsrfToken.php',
        'csrf_protection' => 'app/Http/Kernel.php',
        'debug_tools' => 'composer.json',
        'dependency_audit' => 'composer.lock',
        'env_hygiene' => 'composer.json',
        'framework_eol' => 'composer.json',
        'horizon_exposure' => 'config/horizon.php',
        'https_posture' => 'config/app.php',
        'ignition_exposure' => 'composer.json',
        'laravel_debug_mode' => 'config/app.php',
        'security_headers' => 'app/Http/Kernel.php',
        'session_configuration' => 'config/session.php',
        'session_storage' => 'config/session.php',
        'telescope_exposure' => 'config/telescope.php',
    ];

    public function __construct(private readonly string $version = 'dev') {}

    /**
     * @param  array<int, CheckResult>  $results
     */
    public function format(array $results, string $environment): string
    {
        $reported = array_values(array_filter(
            $results,
            fn (CheckResult $r) => in_array($r->status, [CheckResult::FAIL, CheckResult::WARNING], true)
        ));

        return json_encode([
            '$schema' => self::SCHEMA,
            'version' => '2.1.0',
            'runs' => [[
                'tool' => ['driver' => [
                    'name' => 'StackShield Scanner',
                    'informationUri' => 'https://stackshield.io',
                    'version' => $this->version,
                    'rules' => array_map([$this, 'rule'], $reported),
                ]],
                'automationDetails' => ['id' => "stackshield-inside/{$environment}"],
                'results' => array_map([$this, 'result'], $reported),
            ]],
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) ?: '{}';
    }

    private function rule(CheckResult $r): array
    {
        $slug = self::HELP_URIS[$r->slug] ?? null;

        return [
            'id' => $r->slug,
            'name' => str_replace(' ', '', ucwords(str_replace('_', ' ', $r->slug))),
            'shortDescription' => ['text' => $this->title($r->slug)],
            'fullDescription' => ['text' => $r->summary],
            'helpUri' => $slug
                ? "https://stackshield.io/security-checks/{$slug}"
                : 'https://stackshield.io/security-checks',
            'defaultConfiguration' => ['level' => $this->level($r)],
            'properties' => [
                'view' => 'inside',
                'security-severity' => (string) $this->securitySeverity($r),
                'tags' => ['security', 'laravel', 'stackshield'],
            ],
        ];
    }

    private function result(CheckResult $r): array
    {
        return [
            'ruleId' => $r->slug,
            'level' => $this->level($r),
            'message' => ['text' => $r->summary],
            'locations' => [[
                'physicalLocation' => [
                    'artifactLocation' => [
                        'uri' => self::LOCATIONS[$r->slug] ?? 'composer.json',
                        'uriBaseId' => '%SRCROOT%',
                    ],
                ],
            ]],
            'partialFingerprints' => [
                'stackshieldSlug' => $r->slug,
            ],
        ];
    }

    /** SARIF levels are error, warning, note, none. */
    private function level(CheckResult $r): string
    {
        if ($r->status === CheckResult::WARNING) {
            return 'warning';
        }

        return match ($r->severity) {
            'critical', 'high' => 'error',
            'medium' => 'warning',
            default => 'note',
        };
    }

    /** GitHub reads security-severity as a CVSS-like number to bucket findings. */
    private function securitySeverity(CheckResult $r): float
    {
        return match ($r->severity) {
            'critical' => 9.5,
            'high' => 7.5,
            'medium' => 5.0,
            'low' => 3.0,
            default => 1.0,
        };
    }

    private function title(string $slug): string
    {
        return ucfirst(str_replace('_', ' ', $slug));
    }
}
