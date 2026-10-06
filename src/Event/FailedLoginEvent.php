<?php

declare(strict_types=1);

namespace Marko\Authentication\Event;

use Marko\Core\Event\Event;

class FailedLoginEvent extends Event
{
    /**
     * Credential keys matching this pattern (case-insensitive, at any nesting
     * depth) are stripped before the credentials reach listeners or logs.
     */
    public const string SENSITIVE_KEY_PATTERN = '/password|secret|token|otp|pin|passcode/i';

    /**
     * @var array<string, mixed>
     */
    public readonly array $credentials;

    /**
     * @param array<string, mixed> $credentials
     */
    public function __construct(
        array $credentials,
        public readonly string $guard,
    ) {
        $this->credentials = $this->redact($credentials);
    }

    /**
     * @return array<string, mixed>
     */
    public function getCredentials(): array
    {
        return $this->credentials;
    }

    public function getGuard(): string
    {
        return $this->guard;
    }

    /**
     * @param array<array-key, mixed> $credentials
     * @return array<array-key, mixed>
     */
    private function redact(
        array $credentials,
    ): array {
        $redacted = [];

        foreach ($credentials as $key => $value) {
            if (preg_match(self::SENSITIVE_KEY_PATTERN, (string) $key) === 1) {
                continue;
            }

            $redacted[$key] = is_array($value) ? $this->redact($value) : $value;
        }

        return $redacted;
    }
}
