<?php

namespace StackShield\Scanner\Reporting;

use Illuminate\Support\Facades\Http;
use StackShield\Scanner\Results\CheckResult;

/**
 * Sends results to StackShield. Constructed only when a token is present AND
 * reporting is active, so its mere existence guarantees the transmission was
 * intended. It never logs the token.
 */
class Reporter
{
    public function __construct(
        protected string $endpoint,
        protected string $token,
        protected int $timeout = 20,
    ) {}

    /**
     * Submit an inside-view result set. Returns the decoded response body.
     *
     * @param  array<int, CheckResult>  $results
     * @param  array<string, mixed>  $meta  package_version, environment, origin, check_id|domain
     * @return array<string, mixed>
     */
    public function reportLocal(array $results, array $meta): array
    {
        return $this->post('/results', array_merge($meta, [
            'results' => array_map(fn (CheckResult $r) => $r->toReportArray(), $results),
        ]));
    }

    /**
     * Submit a combined deploy scan: stores the inside-view results and triggers
     * the outside-view external scan, grouped as one event.
     *
     * @param  array<int, CheckResult>  $results
     * @param  array<string, mixed>  $meta
     * @return array<string, mixed>
     */
    public function reportDeployScan(array $results, array $meta): array
    {
        return $this->post('/deploy-scans', array_merge($meta, [
            'results' => array_map(fn (CheckResult $r) => $r->toReportArray(), $results),
        ]));
    }

    /** Poll an external scan's status (used while waiting for a combined scan). */
    public function scanStatus(string $scanId): ?array
    {
        try {
            $response = $this->client()->get($this->url("/scans/{$scanId}"));
        } catch (\Throwable) {
            return null;
        }

        return $response->successful() ? (array) $response->json() : null;
    }

    protected function post(string $path, array $payload): array
    {
        $response = $this->client()->post($this->url($path), $payload);

        return [
            'ok' => $response->successful(),
            'status' => $response->status(),
            'body' => $response->json() ?? [],
        ];
    }

    protected function client()
    {
        return Http::withToken($this->token)
            ->timeout($this->timeout)
            ->acceptJson()
            ->withHeaders(['User-Agent' => 'stackshield-scanner']);
    }

    protected function url(string $path): string
    {
        return rtrim($this->endpoint, '/').'/'.ltrim($path, '/');
    }
}
