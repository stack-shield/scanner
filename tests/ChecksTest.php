<?php

namespace StackShield\Scanner\Tests;

use Illuminate\Support\Facades\Http;
use StackShield\Scanner\Checks\AppKeyCheck;
use StackShield\Scanner\Checks\CorsConfigurationCheck;
use StackShield\Scanner\Checks\CsrfExemptionsCheck;
use StackShield\Scanner\Checks\CsrfProtectionCheck;
use StackShield\Scanner\Checks\DebugModeCheck;
use StackShield\Scanner\Checks\DependencyAuditCheck;
use StackShield\Scanner\Checks\SessionStorageCheck;
use StackShield\Scanner\Dependencies\LockFileAuditor;
use StackShield\Scanner\Dependencies\PackagistAdvisoryClient;
use StackShield\Scanner\Probes\ScanContext;
use StackShield\Scanner\Results\CheckResult;

class ChecksTest extends TestCase
{
    protected function context(bool $offline = false): ScanContext
    {
        return new ScanContext($this->app, syntheticEnabled: false, offline: $offline);
    }

    public function test_debug_mode_is_critical_in_production(): void
    {
        config()->set('app.debug', true);
        config()->set('app.env', 'production');

        $result = (new DebugModeCheck)->run($this->context());

        $this->assertSame(CheckResult::FAIL, $result->status);
        $this->assertSame('critical', $result->severity);
    }

    public function test_debug_mode_is_informational_in_local(): void
    {
        config()->set('app.debug', true);
        config()->set('app.env', 'local');

        $result = (new DebugModeCheck)->run($this->context());

        // Debug on in local is expected, not a finding.
        $this->assertSame(CheckResult::PASS, $result->status);
    }

    public function test_app_key_empty_is_critical(): void
    {
        config()->set('app.key', '');

        $result = (new AppKeyCheck)->run($this->context());

        $this->assertSame(CheckResult::FAIL, $result->status);
        $this->assertSame('critical', $result->severity);
    }

    public function test_cors_wildcard_with_credentials_is_high(): void
    {
        config()->set('cors.allowed_origins', ['*']);
        config()->set('cors.supports_credentials', true);

        $result = (new CorsConfigurationCheck)->run($this->context());

        $this->assertSame(CheckResult::FAIL, $result->status);
        $this->assertSame('high', $result->severity);
    }

    public function test_cookie_session_driver_without_encryption_fails(): void
    {
        config()->set('session.driver', 'cookie');
        config()->set('session.encrypt', false);

        $result = (new SessionStorageCheck)->run($this->context());

        $this->assertSame(CheckResult::FAIL, $result->status);
    }

    public function test_csrf_protection_passes_on_the_framework_default_web_group(): void
    {
        // The default group registers ValidateCsrfToken on Laravel 11 and 12 and
        // PreventRequestForgery on Laravel 13. Both are CSRF protection.
        $result = (new CsrfProtectionCheck)->run($this->context());

        $this->assertSame(CheckResult::PASS, $result->status);
    }

    public function test_csrf_exemptions_include_paths_registered_in_bootstrap(): void
    {
        $class = class_exists('Illuminate\\Foundation\\Http\\Middleware\\PreventRequestForgery')
            ? 'Illuminate\\Foundation\\Http\\Middleware\\PreventRequestForgery'
            : 'Illuminate\\Foundation\\Http\\Middleware\\VerifyCsrfToken';

        if (! method_exists($class, 'except')) {
            $this->markTestSkipped('This Laravel version has no static CSRF exclusion list.');
        }

        // What ->validateCsrfTokens(except: [...]) in bootstrap/app.php does.
        $class::except(['*']);

        try {
            $result = (new CsrfExemptionsCheck)->run($this->context());
        } finally {
            $class::flushState();
        }

        $this->assertSame(CheckResult::FAIL, $result->status);
        $this->assertSame('high', $result->severity);
    }

    public function test_dependency_audit_skipped_when_offline(): void
    {
        $result = (new DependencyAuditCheck)->run($this->context(offline: true));

        $this->assertSame(CheckResult::NOT_APPLICABLE, $result->status);
    }

    public function test_dependency_audit_flags_a_vulnerable_lock(): void
    {
        Http::fake([
            'packagist.org/api/security-advisories*' => Http::response([
                'advisories' => [
                    'symfony/http-kernel' => [[
                        'advisoryId' => 'PKSA-x',
                        'cve' => 'CVE-2022-24894',
                        'title' => 'Cookie header leak',
                        'affectedVersions' => '>=5.4.0,<5.4.20',
                        'severity' => 'medium',
                    ]],
                ],
            ], 200),
        ]);

        $lock = json_encode(['packages' => [
            ['name' => 'symfony/http-kernel', 'version' => 'v5.4.10'],
        ]]);
        $auditor = new LockFileAuditor(new PackagistAdvisoryClient);
        $matches = $auditor->audit($lock);

        $this->assertCount(1, $matches);
        $this->assertSame('5.4.20', $matches[0]['fixed_version']);
        $this->assertSame('CVE-2022-24894', $matches[0]['cve']);
    }

    public function test_lock_auditor_does_not_recommend_inclusive_upper_bound(): void
    {
        Http::fake([
            'packagist.org/api/security-advisories*' => Http::response([
                'advisories' => [
                    'vendor/pkg' => [[
                        'advisoryId' => 'PKSA-y',
                        'title' => 'Bug',
                        'affectedVersions' => '>=1.0.0,<=1.4.2',
                        'severity' => 'high',
                    ]],
                ],
            ], 200),
        ]);

        $lock = json_encode(['packages' => [['name' => 'vendor/pkg', 'version' => '1.4.2']]]);
        $matches = (new LockFileAuditor(new PackagistAdvisoryClient))->audit($lock);

        $this->assertCount(1, $matches);
        // 1.4.2 is itself affected, so no fixed version is claimed.
        $this->assertNull($matches[0]['fixed_version']);
    }
}
