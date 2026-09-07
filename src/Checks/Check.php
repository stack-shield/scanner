<?php

namespace StackShield\Scanner\Checks;

use StackShield\Scanner\Probes\ScanContext;
use StackShield\Scanner\Results\CheckResult;

/**
 * One inside-view check. Each check declares its catalog slug (so results map
 * cleanly when reported), the probe techniques it uses (for the docs and so a
 * check that needs the network can be skipped with --offline), and runs against
 * the booted application.
 *
 * A check must never throw. Wrap risky probing and return notApplicable() with a
 * reason on any unexpected condition.
 */
interface Check
{
    /** The StackShield catalog slug this check reports against. */
    public function slug(): string;

    /** One or more of: config, registry, synthetic, static. */
    public function techniques(): array;

    /** True if this check needs outbound network (e.g. Packagist). */
    public function needsNetwork(): bool;

    public function run(ScanContext $context): CheckResult;
}
