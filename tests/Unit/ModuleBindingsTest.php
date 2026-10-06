<?php

declare(strict_types=1);

use Marko\Authentication\AuthManager;
use Marko\Authentication\Config\AuthConfig;
use Marko\Authentication\Contracts\GuardInterface;
use Marko\Authentication\Contracts\PasswordHasherInterface;
use Marko\Authentication\Guard\GuardDriverRegistry;
use Marko\Authentication\Hashing\BcryptPasswordHasher;
use Marko\Authentication\Token\RememberTokenManager;
use Marko\Core\Container\ContainerInterface;
use Marko\Testing\Fake\FakeClock;
use Psr\Clock\ClockInterface;

it('has enabled set to true', function () {
    $modulePath = dirname(__DIR__, 2) . '/module.php';

    expect(file_exists($modulePath))->toBeTrue();

    $config = require $modulePath;

    expect($config)->toBeArray();
});

it('has bindings array', function () {
    $modulePath = dirname(__DIR__, 2) . '/module.php';
    $config = require $modulePath;

    expect($config)->toHaveKey('bindings')
        ->and($config['bindings'])->toBeArray();
});

it('binds PasswordHasherInterface to BcryptPasswordHasher', function () {
    $modulePath = dirname(__DIR__, 2) . '/module.php';
    $config = require $modulePath;

    expect($config['bindings'])->toHaveKey(PasswordHasherInterface::class)
        ->and($config['bindings'][PasswordHasherInterface::class])->toBeInstanceOf(Closure::class);
});

it('binds GuardInterface with factory', function () {
    $modulePath = dirname(__DIR__, 2) . '/module.php';
    $config = require $modulePath;

    expect($config['bindings'])->toHaveKey(GuardInterface::class)
        ->and($config['bindings'][GuardInterface::class])->toBeInstanceOf(Closure::class);
});

it('creates password hasher with config cost', function () {
    $modulePath = dirname(__DIR__, 2) . '/module.php';
    $config = require $modulePath;
    $binding = $config['bindings'][PasswordHasherInterface::class];

    $authConfig = $this->createMock(AuthConfig::class);
    $authConfig->expects($this->once())
        ->method('bcryptCost')
        ->willReturn(10);

    $container = $this->createMock(ContainerInterface::class);
    $container->expects($this->once())
        ->method('get')
        ->with(AuthConfig::class)
        ->willReturn($authConfig);

    $result = $binding($container);

    expect($result)->toBeInstanceOf(BcryptPasswordHasher::class)
        ->and($result)->toBeInstanceOf(PasswordHasherInterface::class);
});

it('builds RememberTokenManager with the bound clock from the module', function () {
    $config = require dirname(__DIR__, 2) . '/module.php';
    $binding = $config['bindings'][RememberTokenManager::class];

    $authConfig = $this->createStub(AuthConfig::class);
    $authConfig->method('rememberLifetime')->willReturn(60);
    $clock = new FakeClock('2026-01-01 12:00:00 UTC');

    $container = $this->createStub(ContainerInterface::class);
    $container->method('get')->willReturnCallback(
        fn (string $id): object => match ($id) {
            AuthConfig::class => $authConfig,
            ClockInterface::class => $clock,
        },
    );

    $manager = $binding($container);
    $createdAt = $clock->now();

    $clock->travel('+60 minutes');
    expect($manager->isExpired($createdAt))->toBeFalse();

    $clock->travel('+1 second');
    expect($manager->isExpired($createdAt))->toBeTrue();
});

it('creates guard via AuthManager', function () {
    $modulePath = dirname(__DIR__, 2) . '/module.php';
    $config = require $modulePath;
    $binding = $config['bindings'][GuardInterface::class];

    $guard = $this->createStub(GuardInterface::class);

    $authManager = $this->createMock(AuthManager::class);
    $authManager->expects($this->once())
        ->method('guard')
        ->willReturn($guard);

    $container = $this->createMock(ContainerInterface::class);
    $container->expects($this->once())
        ->method('get')
        ->with(AuthManager::class)
        ->willReturn($authManager);

    $result = $binding($container);

    expect($result)->toBeInstanceOf(GuardInterface::class);
});

it('registers AuthManager as singleton', function () {
    $modulePath = dirname(__DIR__, 2) . '/module.php';
    $config = require $modulePath;

    expect($config)->toHaveKey('singletons')
        ->and($config['singletons'])->toContain(AuthManager::class);
});

it('registers GuardInterface as singleton', function () {
    $modulePath = dirname(__DIR__, 2) . '/module.php';
    $config = require $modulePath;

    expect($config['singletons'])->toContain(GuardInterface::class);
});

it('registers the guard driver registry as a singleton', function () {
    $modulePath = dirname(__DIR__, 2) . '/module.php';
    $config = require $modulePath;

    expect($config['singletons'])->toContain(GuardDriverRegistry::class);
});
