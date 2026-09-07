<?php

namespace StackShield\Scanner\Tests;

use StackShield\Scanner\Reporting\SarifFormatter;
use StackShield\Scanner\Results\CheckResult;

class SarifFormatterTest extends TestCase
{
    /** @return array<int, CheckResult> */
    protected function results(): array
    {
        return [
            CheckResult::fail('laravel_debug_mode', 'critical', 'Debug mode is on in the production environment.'),
            CheckResult::fail('session_configuration', 'medium', 'Session cookie is missing the Secure flag.'),
            CheckResult::warning('framework_eol', 'Laravel 10 reaches end of life soon.'),
            CheckResult::pass('csrf_protection', 'CSRF middleware is registered.'),
            CheckResult::notApplicable('horizon_exposure', 'Horizon is not installed.'),
        ];
    }

    protected function sarif(): array
    {
        return json_decode((new SarifFormatter('1.2.3'))->format($this->results(), 'production'), true);
    }

    public function test_it_emits_valid_sarif_envelope(): void
    {
        $s = $this->sarif();

        $this->assertSame('2.1.0', $s['version']);
        $this->assertStringContainsString('sarif-schema-2.1.0', $s['$schema']);
        $this->assertCount(1, $s['runs']);
        $this->assertSame('StackShield Scanner', $s['runs'][0]['tool']['driver']['name']);
        $this->assertSame('1.2.3', $s['runs'][0]['tool']['driver']['version']);
    }

    public function test_it_reports_only_failures_and_warnings(): void
    {
        $s = $this->sarif();
        $ids = array_column($s['runs'][0]['results'], 'ruleId');

        $this->assertContains('laravel_debug_mode', $ids);
        $this->assertContains('session_configuration', $ids);
        $this->assertContains('framework_eol', $ids);

        // Passes and not-applicable checks are not findings and must not appear,
        // otherwise every clean run would still annotate the pull request.
        $this->assertNotContains('csrf_protection', $ids);
        $this->assertNotContains('horizon_exposure', $ids);
    }

    public function test_it_maps_severity_to_sarif_levels(): void
    {
        $byId = [];
        foreach ($this->sarif()['runs'][0]['results'] as $r) {
            $byId[$r['ruleId']] = $r['level'];
        }

        $this->assertSame('error', $byId['laravel_debug_mode']);
        $this->assertSame('warning', $byId['session_configuration']);
        $this->assertSame('warning', $byId['framework_eol']);
    }

    public function test_every_result_has_a_rule_and_a_location(): void
    {
        $s = $this->sarif();
        $ruleIds = array_column($s['runs'][0]['tool']['driver']['rules'], 'id');

        foreach ($s['runs'][0]['results'] as $r) {
            $this->assertContains($r['ruleId'], $ruleIds, "result {$r['ruleId']} has no matching rule");
            $uri = $r['locations'][0]['physicalLocation']['artifactLocation']['uri'];
            $this->assertNotEmpty($uri);
        }
    }

    public function test_help_uris_are_absolute_and_fall_back_to_the_index(): void
    {
        $byId = [];
        foreach ($this->sarif()['runs'][0]['tool']['driver']['rules'] as $rule) {
            $byId[$rule['id']] = $rule['helpUri'];
        }

        // Has a catalog page on the SaaS.
        $this->assertSame('https://stackshield.io/security-checks/laravel-debug-mode', $byId['laravel_debug_mode']);
        // Has none, so it must fall back rather than emit a 404.
        $this->assertSame('https://stackshield.io/security-checks', $byId['framework_eol']);
    }

    public function test_it_carries_github_security_severity(): void
    {
        $byId = [];
        foreach ($this->sarif()['runs'][0]['tool']['driver']['rules'] as $rule) {
            $byId[$rule['id']] = $rule['properties']['security-severity'];
        }

        $this->assertSame('9.5', $byId['laravel_debug_mode']);
        $this->assertSame('5', $byId['session_configuration']);
    }

    public function test_a_clean_run_emits_an_empty_but_valid_report(): void
    {
        $json = (new SarifFormatter)->format([
            CheckResult::pass('csrf_protection', 'All good.'),
        ], 'production');

        $s = json_decode($json, true);
        $this->assertSame([], $s['runs'][0]['results']);
        $this->assertSame([], $s['runs'][0]['tool']['driver']['rules']);
    }
}
