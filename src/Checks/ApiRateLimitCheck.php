<?php

namespace StackShield\Scanner\Checks;

use StackShield\Scanner\Probes\ScanContext;
use StackShield\Scanner\Results\CheckResult;

/**
 * Auth-shaped routes (login, password reset, registration, token issuance)
 * without a throttle in their middleware stack. Rate limiting these routes is
 * what blunts credential stuffing and brute force.
 */
class ApiRateLimitCheck extends AbstractCheck
{
    protected const AUTH_PATTERNS = ['login', 'password', 'register', 'forgot-password', 'reset-password', 'token', 'oauth', 'two-factor'];

    public function slug(): string
    {
        return 'api_rate_limit';
    }

    public function techniques(): array
    {
        return ['registry'];
    }

    public function run(ScanContext $ctx): CheckResult
    {
        $unthrottled = [];

        foreach ($ctx->routes() as $route) {
            $uri = $route->uri();
            $methods = $route->methods();

            if (! $this->looksLikeAuth($uri) || ! (in_array('POST', $methods, true) || in_array('PUT', $methods, true))) {
                continue;
            }

            $middleware = $this->middleware($route);
            $hasThrottle = (bool) array_filter($middleware, fn ($m) => is_string($m) && str_starts_with($m, 'throttle'));

            if (! $hasThrottle) {
                $unthrottled[] = implode('|', $methods).' /'.ltrim($uri, '/');
            }
        }

        if (empty($unthrottled)) {
            return CheckResult::pass($this->slug(), 'Auth-shaped routes carry a throttle middleware.');
        }

        return CheckResult::fail($this->slug(), 'medium',
            count($unthrottled).' auth-shaped route(s) have no throttle middleware.',
            ['routes' => array_slice($unthrottled, 0, 25)]);
    }

    protected function looksLikeAuth(string $uri): bool
    {
        $uri = strtolower($uri);
        foreach (self::AUTH_PATTERNS as $pattern) {
            if (str_contains($uri, $pattern)) {
                return true;
            }
        }

        return false;
    }

    protected function middleware($route): array
    {
        try {
            return $route->gatherMiddleware();
        } catch (\Throwable) {
            return (array) ($route->middleware() ?? []);
        }
    }
}
