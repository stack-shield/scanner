<?php

namespace StackShield\Scanner;

use StackShield\Scanner\Checks\Check;
use StackShield\Scanner\Probes\ScanContext;
use StackShield\Scanner\Results\CheckResult;

/**
 * Runs the applicable checks against the booted application. A check that throws
 * is reported as not_applicable with the reason; one failing check never aborts
 * the run.
 */
class Scanner
{
    /**
     * @param  array<int, Check>  $checks
     * @param  string[]  $skip  catalog slugs to skip
     * @return array<int, CheckResult>
     */
    public function run(ScanContext $context, array $checks, array $skip = []): array
    {
        $results = [];

        foreach ($checks as $check) {
            $slug = $check->slug();

            if (in_array($slug, $skip, true)) {
                continue;
            }
            if ($context->isOffline() && $check->needsNetwork()) {
                $results[] = CheckResult::notApplicable($slug, 'Skipped in offline mode.');

                continue;
            }

            try {
                $results[] = $check->run($context);
            } catch (\Throwable $e) {
                $results[] = CheckResult::notApplicable($slug, 'Check errored: '.$e->getMessage());
            }
        }

        return $results;
    }
}
