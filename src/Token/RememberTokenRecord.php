<?php

declare(strict_types=1);

namespace Marko\Authentication\Token;

use DateTimeImmutable;

/**
 * One device's remember-me token, as RememberTokenStorageInterface stores it.
 *
 * The cookie carries "selector:validator". The selector finds the row; only
 * the SHA-256 hash of the validator is stored, so a leaked table cannot be
 * replayed as cookies. Each device that ticks "remember me" gets its own row,
 * so logging in or out on one device never touches another.
 */
readonly class RememberTokenRecord
{
    public function __construct(
        public string $guard,
        public int|string $userId,
        public string $selector,
        public string $validatorHash,
        public DateTimeImmutable $expiresAt,
        public ?string $userAgent = null,
    ) {}
}
