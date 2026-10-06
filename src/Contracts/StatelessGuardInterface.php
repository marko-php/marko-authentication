<?php

declare(strict_types=1);

namespace Marko\Authentication\Contracts;

/**
 * A guard that authenticates each request from credentials the request
 * carries (an API token, for example) and keeps no login state between
 * requests.
 *
 * Its clients cannot follow a login redirect, so AuthMiddleware always
 * answers an unauthenticated request on a stateless guard with a 401 that
 * carries this guard's WWW-Authenticate challenge. The stateful methods of
 * GuardInterface (attempt, login, loginById, logout) have no meaning here
 * and must throw an exception that explains how to issue or revoke
 * credentials instead.
 */
interface StatelessGuardInterface extends GuardInterface
{
    /**
     * The WWW-Authenticate challenge sent with a 401, e.g. "Bearer".
     */
    public function getChallenge(): string;
}
