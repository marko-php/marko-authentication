<?php

declare(strict_types=1);

namespace Marko\Authentication\Token;

use DateMalformedStringException;
use DateTimeImmutable;
use Psr\Clock\ClockInterface;
use Random\RandomException;

class RememberTokenManager
{
    private int $lifetimeMinutes;

    public function __construct(
        private readonly ClockInterface $clock,
        ?int $lifetimeMinutes = null,
    ) {
        $this->lifetimeMinutes = $lifetimeMinutes ?? 43200; // 30 days default
    }

    public function lifetimeMinutes(): int
    {
        return $this->lifetimeMinutes;
    }

    /**
     * @throws RandomException
     */
    public function generate(): string
    {
        return bin2hex(random_bytes(32));
    }

    /**
     * A random, non-secret lookup key for a per-device token (the part before the colon in the cookie).
     *
     * @throws RandomException
     */
    public function generateSelector(): string
    {
        return bin2hex(random_bytes(16));
    }

    public function hash(
        string $token,
    ): string {
        return hash('sha256', $token);
    }

    public function validate(
        string $token,
        string $storedHash,
    ): bool {
        return hash_equals($storedHash, $this->hash($token));
    }

    /**
     * When a token issued now stops being accepted.
     *
     * @throws DateMalformedStringException
     */
    public function expiresAt(): DateTimeImmutable
    {
        return $this->clock->now()->modify("+$this->lifetimeMinutes minutes");
    }

    /**
     * Whether a token with the given expiry is no longer accepted.
     */
    public function hasExpired(
        DateTimeImmutable $expiresAt,
    ): bool {
        return $expiresAt <= $this->clock->now();
    }

    /**
     * Whole minutes until the given expiry, at least one, for the cookie lifetime.
     */
    public function minutesUntil(
        DateTimeImmutable $expiresAt,
    ): int {
        $seconds = $expiresAt->getTimestamp() - $this->clock->now()->getTimestamp();

        return max(1, (int) ceil($seconds / 60));
    }

    /**
     * @throws DateMalformedStringException
     */
    public function isExpired(
        DateTimeImmutable $createdAt,
    ): bool {
        $expiresAt = $createdAt->modify("+$this->lifetimeMinutes minutes");

        return $expiresAt < $this->clock->now();
    }

    /**
     * @param array<int, array{hash: string, created_at: DateTimeImmutable}> $tokens
     * @return array<int, array{hash: string, created_at: DateTimeImmutable}>
     * @throws DateMalformedStringException
     */
    public function filterExpired(
        array $tokens,
    ): array {
        return array_values(array_filter(
            $tokens,
            fn (array $token): bool => !$this->isExpired($token['created_at']),
        ));
    }
}
