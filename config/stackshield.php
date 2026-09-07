<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Reporting to StackShield
    |--------------------------------------------------------------------------
    |
    | Nothing is ever sent to StackShield without a token AND reporting being
    | active. No token means no network calls to StackShield, ever. The only
    | network call the package makes without a token is the dependency audit,
    | which talks to Packagist (not StackShield); disable it with --offline.
    |
    */
    'reporting' => [
        // The project API key. Also read from the STACKSHIELD_TOKEN env var.
        'token' => env('STACKSHIELD_TOKEN'),

        // Even with a token present, results are only sent when this is true or
        // the --report flag is passed. --no-report always wins.
        'enabled' => env('STACKSHIELD_REPORT', false),

        // The SaaS ingest endpoint. Override for self-hosted or testing.
        'endpoint' => env('STACKSHIELD_ENDPOINT', 'https://stackshield.io/api/v1'),

        // Default scan URL to associate results with, and whether it is linked to
        // this codebase. Usually passed on the command line instead.
        'url' => env('STACKSHIELD_URL'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Checks
    |--------------------------------------------------------------------------
    */

    // Catalog slugs to skip entirely.
    'skip' => [],

    // The command exits non-zero when a finding at or above this severity is
    // present. One of: critical, high, medium, low.
    'fail_on' => env('STACKSHIELD_FAIL_ON', 'critical'),

    /*
    |--------------------------------------------------------------------------
    | Probes
    |--------------------------------------------------------------------------
    */
    'probes' => [
        // Synthetic in-memory kernel requests boot the full middleware stack and
        // may touch session storage or fire request lifecycle events. Disable to
        // degrade the affected checks to config-only mode.
        'synthetic_requests' => env('STACKSHIELD_SYNTHETIC_REQUESTS', true),
    ],
];
