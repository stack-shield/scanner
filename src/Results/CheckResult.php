<?php

namespace StackShield\Scanner\Results;

/**
 * The outcome of one inside-view check. Statuses mirror the StackShield catalog:
 * pass, fail, warning, not_applicable. A check that cannot run (missing package,
 * probe disabled, unexpected error) returns not_applicable rather than failing.
 */
class CheckResult
{
    public const PASS = 'pass';

    public const FAIL = 'fail';

    public const WARNING = 'warning';

    public const NOT_APPLICABLE = 'not_applicable';

    /**
     * @param  array<string, mixed>  $detail
     */
    private function __construct(
        public readonly string $slug,
        public readonly string $status,
        public readonly ?string $severity,
        public readonly string $summary,
        public readonly array $detail = [],
    ) {}

    public static function pass(string $slug, string $summary, array $detail = []): self
    {
        return new self($slug, self::PASS, null, $summary, $detail);
    }

    public static function fail(string $slug, ?string $severity, string $summary, array $detail = []): self
    {
        return new self($slug, self::FAIL, $severity, $summary, $detail);
    }

    public static function warning(string $slug, string $summary, array $detail = []): self
    {
        return new self($slug, self::WARNING, 'low', $summary, $detail);
    }

    public static function notApplicable(string $slug, string $reason): self
    {
        return new self($slug, self::NOT_APPLICABLE, null, $reason, ['reason' => $reason]);
    }

    public function isFailure(): bool
    {
        return $this->status === self::FAIL;
    }

    /** Severity ranked for exit-code and sorting purposes. Higher is worse. */
    public function severityRank(): int
    {
        return match ($this->severity) {
            'critical' => 4,
            'high' => 3,
            'medium' => 2,
            'low' => 1,
            default => 0,
        };
    }

    /** The payload shape the StackShield ingest endpoint accepts. */
    public function toReportArray(): array
    {
        return [
            'slug' => $this->slug,
            'status' => $this->status,
            'severity' => $this->severity,
            'detail' => array_merge(['summary' => $this->summary], $this->detail),
        ];
    }

    public function toArray(): array
    {
        return [
            'slug' => $this->slug,
            'status' => $this->status,
            'severity' => $this->severity,
            'summary' => $this->summary,
            'detail' => $this->detail,
        ];
    }
}
