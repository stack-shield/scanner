<?php

namespace StackShield\Scanner\Tests;

use Illuminate\Support\Facades\Http;

/**
 * The hard rule: no network calls of any kind to StackShield without a token.
 * No anonymous telemetry, no phone-home. These tests protect that rule.
 */
class NoNetworkWithoutTokenTest extends TestCase
{
    public function test_no_http_calls_at_all_without_a_token_when_offline(): void
    {
        Http::fake();
        config()->set('stackshield.reporting.token', null);

        $this->artisan('stackshield:scan', ['--offline' => true])->assertExitCode(0);

        // Nothing left the machine: not to StackShield, not to Packagist, nowhere.
        Http::assertNothingSent();
    }

    public function test_report_flag_without_token_sends_nothing_to_stackshield(): void
    {
        Http::fake();
        config()->set('stackshield.reporting.token', null);

        $this->artisan('stackshield:scan', ['--offline' => true, '--report' => true])
            ->expectsOutputToContain('no STACKSHIELD_TOKEN is set');

        Http::assertNothingSent();
    }

    public function test_token_present_but_reporting_off_sends_nothing(): void
    {
        Http::fake();
        config()->set('stackshield.reporting.token', 'sk_test');
        config()->set('stackshield.reporting.enabled', false);

        $this->artisan('stackshield:scan', ['--offline' => true])->assertExitCode(0);

        // A token alone never triggers a send.
        Http::assertNothingSent();
    }

    public function test_no_report_flag_overrides_config(): void
    {
        Http::fake();
        config()->set('stackshield.reporting.token', 'sk_test');
        config()->set('stackshield.reporting.enabled', true);

        $this->artisan('stackshield:scan', ['--offline' => true, '--no-report' => true])->assertExitCode(0);

        Http::assertNothingSent();
    }
}
