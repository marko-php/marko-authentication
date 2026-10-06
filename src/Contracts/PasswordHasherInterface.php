<?php

declare(strict_types=1);

namespace Marko\Authentication\Contracts;

interface PasswordHasherInterface
{
    public function hash(
        string $password,
    ): string;

    public function verify(
        string $password,
        string $hash,
    ): bool;

    public function needsRehash(
        string $hash,
    ): bool;

    /**
     * Verify the password against a fixed dummy hash of the configured cost, discarding the result.
     *
     * User providers call this when no account can be checked (unknown or inactive user), so a failed
     * login costs the same time as a real password check and response timing does not reveal which
     * accounts exist.
     */
    public function verifyDummy(
        string $password,
    ): void;
}
