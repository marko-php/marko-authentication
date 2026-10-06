<?php

declare(strict_types=1);

namespace Marko\Authentication\Contracts;

/**
 * A guard whose credentials can be scoped to a subset of what the user may
 * do, such as an API token issued with a list of abilities.
 *
 * Authorization (the Gate, and so #[Can]) asks the guard before granting an
 * ability to an authenticated user: when hasAbility() returns false, the
 * ability is denied whatever the user's own permissions or policies say. A
 * credential can narrow a user's authority, never widen it.
 */
interface AbilityScopedGuardInterface extends GuardInterface
{
    /**
     * Whether the credential the current request authenticated with grants
     * the given ability. False when the request carries no valid credential.
     */
    public function hasAbility(
        string $ability,
    ): bool;
}
