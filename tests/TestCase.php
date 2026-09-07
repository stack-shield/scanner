<?php

namespace StackShield\Scanner\Tests;

use Orchestra\Testbench\TestCase as Orchestra;
use StackShield\Scanner\ScannerServiceProvider;

abstract class TestCase extends Orchestra
{
    protected function getPackageProviders($app): array
    {
        return [ScannerServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('stackshield.reporting.endpoint', 'https://stackshield.test/api/v1');
        // A valid, non-default key so AppKeyCheck does not (correctly) fail the
        // bare test app for reasons unrelated to what a given test asserts.
        $app['config']->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
    }
}
