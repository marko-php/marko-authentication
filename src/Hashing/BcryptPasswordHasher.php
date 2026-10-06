<?php

declare(strict_types=1);

namespace Marko\Authentication\Hashing;

use Marko\Authentication\Contracts\PasswordHasherInterface;

class BcryptPasswordHasher implements PasswordHasherInterface
{
    public const int DEFAULT_COST = 12;

    /**
     * Salt and digest of a bcrypt hash no user password is expected to match; the cost prefix is
     * added per instance so a dummy verification costs exactly as much as a real one.
     */
    private const string DUMMY_HASH_BODY = 'ZxSPF.27pFWWE6Ew0jDzE.HiJNsq8davb61hvjFFesMqHyLDmjNbe';

    private int $cost;

    public function __construct(
        ?int $cost = null,
    ) {
        $this->cost = $cost ?? self::DEFAULT_COST;
    }

    public function hash(
        string $password,
    ): string {
        return password_hash($password, PASSWORD_BCRYPT, ['cost' => $this->cost]);
    }

    public function verify(
        string $password,
        string $hash,
    ): bool {
        return password_verify($password, $hash);
    }

    public function needsRehash(
        string $hash,
    ): bool {
        return password_needs_rehash($hash, PASSWORD_BCRYPT, ['cost' => $this->cost]);
    }

    public function verifyDummy(
        string $password,
    ): void {
        password_verify($password, $this->dummyHash());
    }

    private function dummyHash(): string
    {
        return sprintf('$2y$%02d$%s', $this->cost, self::DUMMY_HASH_BODY);
    }
}
