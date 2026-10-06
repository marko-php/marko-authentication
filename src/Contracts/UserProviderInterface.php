<?php

declare(strict_types=1);

namespace Marko\Authentication\Contracts;

use DateTimeImmutable;
use Marko\Authentication\AuthenticatableInterface;

interface UserProviderInterface
{
    /**
     * Retrieve a user by their unique identifier.
     */
    public function retrieveById(
        int|string $identifier,
    ): ?AuthenticatableInterface;

    /**
     * Retrieve a user by the given credentials.
     *
     * @param array<string, mixed> $credentials
     */
    public function retrieveByCredentials(
        array $credentials,
    ): ?AuthenticatableInterface;

    /**
     * Validate a user against the given credentials.
     *
     * @param array<string, mixed> $credentials
     */
    public function validateCredentials(
        AuthenticatableInterface $user,
        array $credentials,
    ): bool;

    /**
     * Re-hash and store the user's password when its stored hash is out of date.
     *
     * SessionGuard calls this only after validateCredentials() has accepted the same credentials.
     * Implementations check PasswordHasherInterface::needsRehash() against the stored hash and,
     * when it returns true, hash the plain password from $credentials and persist the new hash,
     * so raising the cost or switching algorithm upgrades each account on its next login.
     *
     * @param array<string, mixed> $credentials
     */
    public function rehashPasswordIfNeeded(
        AuthenticatableInterface $user,
        array $credentials,
    ): void;

    /**
     * Retrieve a user by their unique identifier and "remember me" token.
     */
    public function retrieveByRememberToken(
        int|string $identifier,
        string $token,
    ): ?AuthenticatableInterface;

    /**
     * Update the "remember me" token and its expiry for the given user in storage.
     *
     * Implementations call $user->setRememberToken($token) and
     * $user->setRememberTokenExpiresAt($expiresAt), then persist both.
     * Both are null when the token is being cleared (logout).
     */
    public function updateRememberToken(
        AuthenticatableInterface $user,
        ?string $token,
        ?DateTimeImmutable $expiresAt,
    ): void;
}
