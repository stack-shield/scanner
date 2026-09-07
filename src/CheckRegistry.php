<?php

namespace StackShield\Scanner;

/**
 * The default set of inside-view checks. Community contributions add a class here
 * (see docs/writing-checks.md).
 */
class CheckRegistry
{
    /** @return array<int, Checks\Check> */
    public static function all(): array
    {
        return [
            new Checks\DebugModeCheck,
            new Checks\SessionConfigurationCheck,
            new Checks\SessionStorageCheck,
            new Checks\SecurityHeadersCheck,
            new Checks\TelescopeExposureCheck,
            new Checks\HorizonExposureCheck,
            new Checks\IgnitionExposureCheck,
            new Checks\DebugToolsCheck,
            new Checks\CsrfProtectionCheck,
            new Checks\CsrfExemptionsCheck,
            new Checks\CookieEncryptionCheck,
            new Checks\CorsConfigurationCheck,
            new Checks\AppKeyCheck,
            new Checks\HttpsPostureCheck,
            new Checks\ApiRateLimitCheck,
            new Checks\FrameworkEolCheck,
            new Checks\DependencyAuditCheck,
        ];
    }
}
