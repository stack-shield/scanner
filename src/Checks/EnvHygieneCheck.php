<?php

namespace StackShield\Scanner\Checks;

use StackShield\Scanner\Probes\ScanContext;
use StackShield\Scanner\Results\CheckResult;

/**
 * Environment file hygiene: .env is gitignored, and no leftover sibling copies
 * (.env.backup, .env.old, and similar) remain on disk.
 */
class EnvHygieneCheck extends AbstractCheck
{
    protected const LEFTOVERS = ['.env.backup', '.env.bak', '.env.old', '.env.save', '.env.orig', '.env~'];

    public function slug(): string
    {
        return 'env_hygiene';
    }

    public function techniques(): array
    {
        return ['static'];
    }

    public function run(ScanContext $ctx): CheckResult
    {
        $problems = [];

        $gitignore = $ctx->readFile('.gitignore');
        if ($gitignore !== null) {
            $ignored = preg_split('/\R/', $gitignore) ?: [];
            $ignored = array_map('trim', $ignored);
            if (! in_array('.env', $ignored, true)) {
                $problems[] = '.env is not listed in .gitignore.';
            }
        }

        $leftovers = [];
        foreach (self::LEFTOVERS as $file) {
            if ($ctx->fileExists($file)) {
                $leftovers[] = $file;
            }
        }
        if (! empty($leftovers)) {
            $problems[] = 'Leftover env files on disk: '.implode(', ', $leftovers).'.';
        }

        if (empty($problems)) {
            return CheckResult::pass($this->slug(), '.env is gitignored and no leftover env files were found.');
        }

        // A committed .env or a readable leftover is a real exposure risk.
        return CheckResult::fail($this->slug(), 'high', implode(' ', $problems), ['leftovers' => $leftovers]);
    }
}
