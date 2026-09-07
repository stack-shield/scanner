<?php

namespace StackShield\Scanner\Commands;

use Composer\InstalledVersions;
use Illuminate\Console\Command;
use StackShield\Scanner\CheckRegistry;
use StackShield\Scanner\Probes\ScanContext;
use StackShield\Scanner\Reporting\Reporter;
use StackShield\Scanner\Reporting\SarifFormatter;
use StackShield\Scanner\Results\CheckResult;
use StackShield\Scanner\Scanner;

class ScanCommand extends Command
{
    protected $signature = 'stackshield:scan
        {--report : Send results to StackShield (requires a token)}
        {--no-report : Never send results, overriding config}
        {--url= : Also trigger an external scan of this URL and combine the two}
        {--register : Register an unknown URL against the project (non-interactive)}
        {--standalone : Mark a registered URL as not linked to this codebase}
        {--linked : Mark a registered URL as linked to this codebase}
        {--offline : Skip checks that need the network (dependency audit)}
        {--async : Do not wait for the external scan to finish}
        {--no-synthetic : Disable synthetic requests (config-only mode)}
        {--fail-on= : Severity that fails the run: critical|high|medium|low}
        {--format=terminal : terminal | json | compact | sarif}
        {--output= : Write the formatted report to this file instead of stdout}';

    protected $description = 'Run StackShield inside-view security checks against this application';

    public function handle(): int
    {
        $env = (string) config('app.env', 'production');
        $offline = (bool) $this->option('offline');
        $synthetic = (bool) config('stackshield.probes.synthetic_requests', true) && ! $this->option('no-synthetic');

        $context = new ScanContext($this->laravel, $synthetic, $offline);
        $results = (new Scanner)->run($context, CheckRegistry::all(), (array) config('stackshield.skip', []));

        $format = $this->option('format');
        if ($format === 'json') {
            $this->emit(json_encode($this->summary($results, $env), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        } elseif ($format === 'sarif') {
            $this->emit((new SarifFormatter($this->packageVersion()))->format($results, $env));
        } elseif ($format === 'compact') {
            $this->renderCompact($results, $env);
        } else {
            $this->renderTerminal($results, $env);
        }

        $externalCritical = $this->maybeReport($results, $env);

        $failOn = $this->option('fail-on') ?: config('stackshield.fail_on', 'critical');
        $localFail = $this->breaches($results, $failOn);

        return ($localFail || $externalCritical) ? self::FAILURE : self::SUCCESS;
    }

    /**
     * Report if a token is present and reporting is active. Returns true when a
     * combined external scan came back with a critical finding.
     *
     * @param  array<int, CheckResult>  $results
     */
    protected function maybeReport(array $results, string $env): bool
    {
        $token = config('stackshield.reporting.token');
        $active = ! $this->option('no-report')
            && ($this->option('report') || (bool) config('stackshield.reporting.enabled'));

        if (! $active) {
            // Token present but reporting off: one informational line, never a nag.
            if ($token && ! $this->option('no-report')) {
                $this->newLine();
                $this->line('Results were not sent. Run with --report to send them to StackShield.');
            }

            return false;
        }

        if (! $token) {
            $this->newLine();
            $this->warn('Reporting was requested but no STACKSHIELD_TOKEN is set. Nothing was sent.');

            return false;
        }

        $reporter = new Reporter(config('stackshield.reporting.endpoint'), $token);
        $url = $this->option('url') ?: config('stackshield.reporting.url');

        return $url
            ? $this->reportCombined($reporter, $results, $env, $url)
            : $this->reportLocal($reporter, $results, $env);
    }

    /** @param array<int, CheckResult> $results */
    protected function reportLocal(Reporter $reporter, array $results, string $env): bool
    {
        $response = $reporter->reportLocal($results, [
            'origin' => 'local',
            'environment' => $env,
            'package_version' => $this->packageVersion(),
        ]);

        $this->newLine();
        if ($response['ok'] ?? false) {
            $this->info('Inside-view results sent to StackShield.');
        } else {
            $this->warn('Could not send results to StackShield (HTTP '.($response['status'] ?? '?').').');
        }

        return false;
    }

    /** @param array<int, CheckResult> $results */
    protected function reportCombined(Reporter $reporter, array $results, string $env, string $url): bool
    {
        $response = $reporter->reportDeployScan($results, [
            'origin' => 'ci',
            'environment' => $env,
            'package_version' => $this->packageVersion(),
            'domain' => $url,
            'register' => (bool) $this->option('register'),
            'standalone' => (bool) $this->option('standalone'),
            'trigger_external' => true,
        ]);

        $this->newLine();
        if (! ($response['ok'] ?? false)) {
            $this->warn('Combined scan could not start (HTTP '.($response['status'] ?? '?').'): '.($response['body']['error'] ?? 'unknown error'));

            return false;
        }

        $this->info('Inside-view results sent and an outside-view scan of '.$url.' was triggered.');
        $scanId = $response['body']['external_scan_id'] ?? null;

        if (! $scanId || $this->option('async')) {
            return false;
        }

        return $this->waitForExternal($reporter, $scanId);
    }

    protected function waitForExternal(Reporter $reporter, string $scanId): bool
    {
        $this->line('Waiting for the outside-view scan to finish...');
        $deadline = time() + 300;

        while (time() < $deadline) {
            sleep(5);
            $status = $reporter->scanStatus($scanId);
            if (($status['status'] ?? null) === 'completed') {
                $critical = (bool) ($status['has_critical_issues'] ?? false);
                $this->line('Outside-view scan finished. Critical issues: '.($critical ? 'yes' : 'no'));

                return $critical;
            }
            if (($status['status'] ?? null) === 'failed') {
                $this->warn('Outside-view scan failed.');

                return false;
            }
        }

        $this->warn('Timed out waiting for the outside-view scan.');

        return false;
    }

    /** @param array<int, CheckResult> $results */
    protected function renderTerminal(array $results, string $env): void
    {
        $this->newLine();
        $this->line('  <options=bold>StackShield inside view</>  (self-reported, unverified)');
        $this->line('  Environment evaluated: <options=bold>'.$env.'</>');
        $this->newLine();

        foreach ($this->sorted($results) as $r) {
            $this->line('  '.$this->badge($r).'  '.$r->slug.$this->severityTag($r));
            $this->line('        <fg=gray>'.$r->summary.'</>');
        }

        $counts = $this->counts($results);
        $this->newLine();
        $this->line(sprintf('  %d passed, %d failed, %d warning, %d not applicable',
            $counts['pass'], $counts['fail'], $counts['warning'], $counts['not_applicable']));
        $this->newLine();
        $this->line('  <fg=gray>This is the inside view: config and runtime posture reported by your codebase.</>');
        $this->line('  <fg=gray>The outside view, what attackers actually see, is verified by StackShield.</>');
        $this->line('  <fg=gray>Run a free external scan at https://stackshield.io</>');
        $this->newLine();
    }

    /** @param array<int, CheckResult> $results */
    protected function renderCompact(array $results, string $env): void
    {
        $c = $this->counts($results);
        $this->line("stackshield inside view [{$env}]: {$c['pass']} pass, {$c['fail']} fail, {$c['warning']} warn, {$c['not_applicable']} n/a");
        foreach ($this->sorted($results) as $r) {
            if ($r->isFailure()) {
                $this->line("  fail [{$r->severity}] {$r->slug}: {$r->summary}");
            }
        }
    }

    /** @param array<int, CheckResult> $results */
    /**
     * Write a machine-readable report to --output when given, stdout otherwise.
     * Writing to a file keeps the payload out of CI logs, which matters for SARIF
     * because the uploader wants a path anyway.
     */
    protected function emit(string $payload): void
    {
        $path = $this->option('output');

        if (! $path) {
            $this->line($payload);

            return;
        }

        $dir = dirname($path);
        if (! is_dir($dir)) {
            mkdir($dir, 0755, true);
        }

        file_put_contents($path, $payload.PHP_EOL);
        $this->info("Report written to {$path}");
    }

    protected function summary(array $results, string $env): array
    {
        return [
            'view' => 'inside',
            'environment' => $env,
            'counts' => $this->counts($results),
            'results' => array_map(fn (CheckResult $r) => $r->toArray(), $results),
        ];
    }

    /** @param array<int, CheckResult> $results */
    protected function counts(array $results): array
    {
        $c = ['pass' => 0, 'fail' => 0, 'warning' => 0, 'not_applicable' => 0];
        foreach ($results as $r) {
            $c[$r->status] = ($c[$r->status] ?? 0) + 1;
        }

        return $c;
    }

    /** @param array<int, CheckResult> $results */
    protected function sorted(array $results): array
    {
        usort($results, fn (CheckResult $a, CheckResult $b) => $b->severityRank() <=> $a->severityRank());

        return $results;
    }

    /** @param array<int, CheckResult> $results */
    protected function breaches(array $results, string $failOn): bool
    {
        $threshold = ['critical' => 4, 'high' => 3, 'medium' => 2, 'low' => 1][$failOn] ?? 4;
        foreach ($results as $r) {
            if ($r->isFailure() && $r->severityRank() >= $threshold) {
                return true;
            }
        }

        return false;
    }

    protected function badge(CheckResult $r): string
    {
        return match ($r->status) {
            CheckResult::PASS => '<fg=green>PASS</>',
            CheckResult::FAIL => '<fg=red>FAIL</>',
            CheckResult::WARNING => '<fg=yellow>WARN</>',
            default => '<fg=gray>N/A </>',
        };
    }

    protected function severityTag(CheckResult $r): string
    {
        return $r->isFailure() && $r->severity ? " <fg=red>[{$r->severity}]</>" : '';
    }

    protected function packageVersion(): string
    {
        return InstalledVersions::getPrettyVersion('stackshield/scanner') ?? 'dev';
    }
}
