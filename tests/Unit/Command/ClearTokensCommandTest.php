<?php

declare(strict_types=1);

use Marko\Authentication\Command\ClearTokensCommand;
use Marko\Authentication\Tests\Fixtures\InMemoryRememberTokenStorage;
use Marko\Authentication\Token\RememberTokenRecord;
use Marko\Core\Attributes\Command;
use Marko\Core\Command\Input;
use Marko\Core\Command\Output;
use Marko\Testing\Fake\FakeClock;

it('has correct command name auth:clear-tokens', function (): void {
    $reflection = new ReflectionClass(ClearTokensCommand::class);
    $attributes = $reflection->getAttributes(Command::class);

    expect($attributes)->toHaveCount(1);

    $command = $attributes[0]->newInstance();
    expect($command->name)->toBe('auth:clear-tokens');
});

it('has description', function (): void {
    $reflection = new ReflectionClass(ClearTokensCommand::class);
    $attributes = $reflection->getAttributes(Command::class);
    $command = $attributes[0]->newInstance();

    expect($command->description)->not->toBeEmpty();
});

it('declares force as a flag', function (): void {
    $command = new ReflectionClass(ClearTokensCommand::class)->getAttributes(Command::class)[0]->newInstance();

    expect($command->flags)->toBe(['force']);
});

/**
 * Storage holding $expired expired and $live unexpired tokens.
 */
function storageWithTokens(
    int $expired,
    int $live,
): InMemoryRememberTokenStorage {
    $clock = new FakeClock('2026-01-01 12:00:00');
    $storage = new InMemoryRememberTokenStorage($clock);

    foreach (range(1, $expired + $live) as $i) {
        $storage->store(new RememberTokenRecord(
            guard: 'session',
            userId: $i,
            selector: "selector-$i",
            validatorHash: hash('sha256', "validator-$i"),
            expiresAt: $clock->now()->modify($i <= $expired ? '-1 minute' : '+1 day'),
        ));
    }

    return $storage;
}

/**
 * @return array{int, string} The exit code and what the command wrote
 */
function runClearTokens(
    ClearTokensCommand $command,
    string ...$arguments,
): array {
    $stream = fopen('php://memory', 'r+');
    $result = $command->execute(new Input(['marko', 'auth:clear-tokens', ...$arguments]), new Output($stream));
    rewind($stream);

    return [$result, (string) stream_get_contents($stream)];
}

it('clears expired tokens and keeps unexpired ones', function (): void {
    $storage = storageWithTokens(expired: 3, live: 2);

    [$result, $content] = runClearTokens(new ClearTokensCommand($storage));

    expect($result)->toBe(0)
        ->and($storage->tokens)->toHaveCount(2)
        ->and($storage->findBySelector('session', 'selector-4'))->not->toBeNull()
        ->and($storage->findBySelector('session', 'selector-1'))->toBeNull()
        ->and($content)->toContain('Cleared 3 expired token(s).');
});

it('handles no expired tokens gracefully', function (): void {
    $storage = storageWithTokens(expired: 0, live: 2);

    [$result, $content] = runClearTokens(new ClearTokensCommand($storage));

    expect($result)->toBe(0)
        ->and($storage->tokens)->toHaveCount(2)
        ->and($content)->toContain('No expired tokens');
});

it('supports --force flag for all tokens', function (): void {
    $storage = storageWithTokens(expired: 2, live: 8);

    [$result, $content] = runClearTokens(new ClearTokensCommand($storage), '--force');

    expect($result)->toBe(0)
        ->and($storage->tokens)->toBe([])
        ->and($content)->toContain('Cleared all 10 token(s).');
});
