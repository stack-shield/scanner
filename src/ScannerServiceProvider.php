<?php

namespace StackShield\Scanner;

use Illuminate\Support\ServiceProvider;
use StackShield\Scanner\Commands\ScanCommand;

class ScannerServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/stackshield.php', 'stackshield');
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([ScanCommand::class]);

            $this->publishes([
                __DIR__.'/../config/stackshield.php' => $this->app->configPath('stackshield.php'),
            ], 'stackshield-config');
        }
    }
}
