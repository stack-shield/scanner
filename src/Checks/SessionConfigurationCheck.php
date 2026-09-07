<?php

namespace StackShield\Scanner\Checks;

use StackShield\Scanner\Probes\ScanContext;
use StackShield\Scanner\Results\CheckResult;

/**
 * Session cookie flags. Prefers the actually-emitted Set-Cookie on a synthetic
 * response; falls back to config when synthetic requests are disabled.
 */
class SessionConfigurationCheck extends AbstractCheck
{
    public function slug(): string
    {
        return 'session_configuration';
    }

    public function techniques(): array
    {
        return ['config', 'synthetic'];
    }

    public function run(ScanContext $ctx): CheckResult
    {
        $flags = $this->fromSyntheticResponse($ctx) ?? $this->fromConfig($ctx);

        $problems = [];
        if (! $flags['http_only']) {
            $problems[] = 'HttpOnly is not set (cookie is readable by JavaScript).';
        }
        if (! $flags['secure'] && $ctx->isProductionLike()) {
            $problems[] = 'Secure is not set (cookie can be sent over plain HTTP).';
        }
        if (in_array(strtolower((string) $flags['same_site']), ['', 'none'], true)) {
            $problems[] = 'SameSite is not restrictive.';
        }

        if (empty($problems)) {
            return CheckResult::pass($this->slug(), 'Session cookie flags are set correctly.', $flags + ['source' => $flags['source']]);
        }

        // Missing Secure in production is the most serious; otherwise medium.
        $severity = (! $flags['secure'] && $ctx->isProductionLike()) ? 'high' : 'medium';

        return CheckResult::fail($this->slug(), $severity,
            'Session cookie flags need attention: '.implode(' ', $problems), $flags);
    }

    protected function fromSyntheticResponse(ScanContext $ctx): ?array
    {
        $response = $ctx->syntheticGet('/');
        if ($response === null) {
            return null;
        }

        foreach ($response->headers->getCookies() as $cookie) {
            // The session cookie is the one whose name matches the session config.
            if ($cookie->getName() === $ctx->config('session.cookie')) {
                return [
                    'http_only' => $cookie->isHttpOnly(),
                    'secure' => $cookie->isSecure(),
                    'same_site' => $cookie->getSameSite() ?? '',
                    'source' => 'synthetic',
                ];
            }
        }

        return null; // no session cookie emitted; fall back to config
    }

    protected function fromConfig(ScanContext $ctx): array
    {
        return [
            'http_only' => (bool) $ctx->config('session.http_only', true),
            'secure' => (bool) $ctx->config('session.secure', false),
            'same_site' => (string) ($ctx->config('session.same_site') ?? ''),
            'source' => 'config',
        ];
    }
}
