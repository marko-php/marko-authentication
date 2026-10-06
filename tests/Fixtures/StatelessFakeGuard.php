<?php

declare(strict_types=1);

namespace Marko\Authentication\Tests\Fixtures;

use Marko\Authentication\Contracts\GuardInterface;
use Marko\Authentication\Contracts\StatelessGuardInterface;
use Marko\Authentication\Guard\GuardDriverRegistry;
use Marko\Testing\Fake\FakeGuard;

/**
 * A FakeGuard that declares itself stateless, standing in for a token guard
 * in marko/authentication's own tests (the real one ships in
 * marko/authentication-token).
 */
class StatelessFakeGuard extends FakeGuard implements StatelessGuardInterface
{
    public function getChallenge(): string
    {
        return 'Bearer';
    }

    /**
     * A registry whose 'token' driver builds a StatelessFakeGuard.
     */
    public static function tokenDriverRegistry(): GuardDriverRegistry
    {
        $registry = new GuardDriverRegistry();
        $registry->extend(
            'token',
            fn (string $name): GuardInterface => new self(name: $name),
        );

        return $registry;
    }
}
