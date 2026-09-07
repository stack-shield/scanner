<?php

namespace StackShield\Scanner\Tests;

use Illuminate\Support\Facades\Http;

class ReportingTest extends TestCase
{
    public function test_report_with_token_posts_inside_view_results(): void
    {
        Http::fake([
            'stackshield.test/api/v1/results' => Http::response(['stored' => 5], 201),
        ]);
        config()->set('stackshield.reporting.token', 'sk_test');

        $this->artisan('stackshield:scan', ['--offline' => true, '--report' => true])
            ->expectsOutputToContain('sent to StackShield');

        Http::assertSent(function ($request) {
            return str_ends_with($request->url(), '/api/v1/results')
                && $request->hasHeader('Authorization', 'Bearer sk_test')
                && is_array($request['results'])
                && $request['origin'] === 'local';
        });
    }

    public function test_combined_url_flow_posts_a_deploy_scan(): void
    {
        Http::fake([
            'stackshield.test/api/v1/deploy-scans' => Http::response([
                'deploy_scan_id' => 'ds_1',
                'external_scan_id' => 'scan_1',
            ], 201),
        ]);
        config()->set('stackshield.reporting.token', 'sk_test');

        // --async so we do not poll the external scan in the test.
        $this->artisan('stackshield:scan', [
            '--offline' => true,
            '--report' => true,
            '--url' => 'https://staging.example.com',
            '--register' => true,
            '--async' => true,
        ])->expectsOutputToContain('outside-view scan of https://staging.example.com was triggered');

        Http::assertSent(function ($request) {
            return str_ends_with($request->url(), '/api/v1/deploy-scans')
                && $request['domain'] === 'https://staging.example.com'
                && $request['register'] === true
                && $request['trigger_external'] === true
                && $request['origin'] === 'ci';
        });
    }

    public function test_json_format_emits_machine_readable_output(): void
    {
        config()->set('stackshield.reporting.token', null);

        $this->artisan('stackshield:scan', ['--offline' => true, '--format' => 'json'])
            ->assertExitCode(0);
    }
}
