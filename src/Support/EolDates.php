<?php

namespace StackShield\Scanner\Support;

/**
 * PHP and Laravel security end-of-life dates. EOL status is computed against the
 * current date, never hardcoded. Update as new versions ship.
 */
class EolDates
{
    /** @var array<string, string> keyed by major.minor */
    public const PHP = [
        '7.2' => '2019-11-30',
        '7.3' => '2021-12-06',
        '7.4' => '2022-11-28',
        '8.0' => '2023-11-26',
        '8.1' => '2025-12-31',
        '8.2' => '2026-12-31',
        '8.3' => '2027-12-31',
        '8.4' => '2028-12-31',
        '8.5' => '2029-12-31',
    ];

    /** @var array<string, string> keyed by major */
    public const LARAVEL = [
        '8' => '2022-01-25',
        '9' => '2024-02-08',
        '10' => '2025-02-04',
        '11' => '2026-03-12',
        '12' => '2027-03-01',
    ];

    public static function laravelEolDate(string $version): ?string
    {
        $major = explode('.', ltrim($version, 'vV'))[0] ?? null;

        return $major !== null ? (self::LARAVEL[$major] ?? null) : null;
    }

    public static function isPast(string $isoDate, ?\DateTimeInterface $now = null): bool
    {
        $now = $now ?? new \DateTimeImmutable('now');

        return $now > new \DateTimeImmutable($isoDate);
    }
}
