<?php

namespace StackShield\Scanner\Probes;

use Illuminate\Contracts\Auth\Access\Gate;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Http\Request;
use Illuminate\Routing\RouteCollectionInterface;
use Symfony\Component\HttpFoundation\Response;

/**
 * Everything a check needs to inspect the live, booted application. This is the
 * home of the four probe techniques:
 *   1. Config introspection      -> config()
 *   2. Registry introspection    -> classExists(), routes(), middlewareGroups()
 *   3. Synthetic kernel requests -> syntheticGet()
 *   4. Static file analysis      -> basePath(), readFile()
 *
 * Environment awareness cuts across all of them: severityInProduction() returns
 * a real severity only when the app is evaluated in a production-like env.
 */
class ScanContext
{
    public function __construct(
        protected Application $app,
        protected bool $syntheticEnabled = true,
        protected bool $offline = false,
    ) {}

    public function environment(): string
    {
        return (string) $this->config('app.env', 'production');
    }

    /** Debug tooling on in these envs is a real finding; elsewhere informational. */
    public function isProductionLike(): bool
    {
        return in_array($this->environment(), ['production', 'staging', 'prod'], true);
    }

    public function isOffline(): bool
    {
        return $this->offline;
    }

    public function config(string $key, mixed $default = null): mixed
    {
        return $this->app['config']->get($key, $default);
    }

    public function classExists(string $class): bool
    {
        return class_exists($class);
    }

    /** Whether an authorization gate ability is defined (e.g. viewTelescope). */
    public function gateExists(string $ability): bool
    {
        try {
            return $this->app->make(Gate::class)->has($ability);
        } catch (\Throwable) {
            return false;
        }
    }

    public function basePath(string $path = ''): string
    {
        return $this->app->basePath($path);
    }

    public function readFile(string $relativePath): ?string
    {
        $full = $this->basePath($relativePath);

        return is_file($full) ? (file_get_contents($full) ?: null) : null;
    }

    public function fileExists(string $relativePath): bool
    {
        return file_exists($this->basePath($relativePath));
    }

    /** @return RouteCollectionInterface */
    public function routes()
    {
        return $this->app['router']->getRoutes();
    }

    /** @return array<string, array<int, mixed>> */
    public function middlewareGroups(): array
    {
        try {
            return $this->app->make(Kernel::class)->getMiddlewareGroups();
        } catch (\Throwable) {
            return [];
        }
    }

    /**
     * Whether the named middleware group contains any of the candidate classes.
     * Returns null when the group cannot be resolved (so the caller can degrade).
     *
     * @param  string[]  $candidates
     */
    public function groupHasMiddleware(string $group, array $candidates): ?bool
    {
        $groups = $this->middlewareGroups();
        if (! array_key_exists($group, $groups)) {
            return null;
        }

        $present = array_map(fn ($m) => is_string($m) ? ltrim($m, '\\') : $m, $groups[$group]);

        foreach ($candidates as $candidate) {
            $candidate = ltrim($candidate, '\\');
            foreach ($present as $middleware) {
                if (is_string($middleware) && (is_a($middleware, $candidate, true) || str_starts_with($middleware, $candidate))) {
                    return true;
                }
            }
        }

        return false;
    }

    public function syntheticEnabled(): bool
    {
        return $this->syntheticEnabled;
    }

    /**
     * Dispatch an in-memory GET request through the full HTTP kernel and return
     * the response. GET/HEAD only, to a controlled path. Returns null when
     * synthetic requests are disabled or anything goes wrong: a check that cannot
     * observe behaviour degrades to config-only mode rather than crashing.
     */
    public function syntheticGet(string $path = '/'): ?Response
    {
        if (! $this->syntheticEnabled) {
            return null;
        }

        // Only ever GET, and only paths we generate ourselves.
        $safePath = '/'.ltrim($path, '/');

        try {
            $kernel = $this->app->make(HttpKernel::class);
            $request = Request::create($safePath, 'GET');
            $response = $kernel->handle($request);
            $kernel->terminate($request, $response);

            return $response;
        } catch (\Throwable) {
            return null;
        }
    }

    /** A path that certainly does not exist, for probing error-page behaviour. */
    public function nonexistentPath(): string
    {
        return '/__stackshield_probe_'.substr(md5((string) mt_rand()), 0, 12);
    }

    /**
     * A severity that only counts in production-like environments. In local/dev
     * the same condition is expected and returned as informational (null).
     */
    public function severityInProduction(string $severity): ?string
    {
        return $this->isProductionLike() ? $severity : null;
    }
}
