<?php

namespace StackShield\Scanner\Dependencies;

use Illuminate\Support\Facades\Http;

/**
 * Fetches security advisories from Packagist. This talks to Packagist, never to
 * StackShield, and is the only outbound network the package makes without a
 * token. Pure HTTP, no composer binary.
 *
 * This is the package's own copy: the scanner is a standalone tool and does not
 * depend on any StackShield service to run its dependency audit.
 */
class PackagistAdvisoryClient
{
    public function __construct(
        protected string $host = 'https://packagist.org',
        protected int $batchSize = 50,
        protected int $timeout = 20,
    ) {}

    /**
     * @param  string[]  $packages
     * @return array<string, array<int, array>> advisories keyed by package name
     */
    public function advisoriesFor(array $packages): array
    {
        $packages = array_values(array_unique(array_filter($packages)));
        $result = [];

        foreach (array_chunk($packages, max(1, $this->batchSize)) as $chunk) {
            $result += $this->fetchBatch($chunk);
        }

        return $result;
    }

    /**
     * @param  string[]  $packages
     * @return array<string, array<int, array>>
     */
    protected function fetchBatch(array $packages): array
    {
        try {
            $response = Http::timeout($this->timeout)
                ->withHeaders(['Accept' => 'application/json', 'User-Agent' => 'stackshield-scanner'])
                ->get($this->host.'/api/security-advisories/', ['packages' => array_values($packages)]);
        } catch (\Throwable) {
            return [];
        }

        if (! $response->successful()) {
            return [];
        }

        $advisories = $response->json('advisories');

        return is_array($advisories) ? $advisories : [];
    }
}
