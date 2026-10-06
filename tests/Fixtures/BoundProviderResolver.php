<?php

declare(strict_types=1);

namespace Marko\Authentication\Tests\Fixtures;

use Marko\Authentication\Config\AuthConfig;
use Marko\Authentication\Contracts\UserProviderInterface;
use Marko\Authentication\UserProviderResolver;
use Marko\Core\Container\Container;
use Marko\Testing\Fake\FakeConfigRepository;

/**
 * Builds a UserProviderResolver for a single-provider app: no
 * authentication.providers config, so every guard gets the container's
 * UserProviderInterface binding, here the given provider.
 */
class BoundProviderResolver
{
    public static function for(
        UserProviderInterface $provider,
    ): UserProviderResolver {
        $container = new Container();
        $container->instance(UserProviderInterface::class, $provider);

        return new UserProviderResolver(new AuthConfig(new FakeConfigRepository([])), $container);
    }
}
