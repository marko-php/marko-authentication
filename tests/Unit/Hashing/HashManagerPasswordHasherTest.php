<?php

declare(strict_types=1);

use Marko\Authentication\Contracts\PasswordHasherInterface;
use Marko\Authentication\Exceptions\InvalidPasswordException;
use Marko\Authentication\Hashing\HashManagerPasswordHasher;
use Marko\Hashing\Config\HashConfig;
use Marko\Hashing\Factory\HasherFactory;
use Marko\Hashing\HashManager;
use Marko\Testing\Fake\FakeConfigRepository;

function hashManagerPasswordHasher(
    string $driver = 'bcrypt',
    int $bcryptCost = 4,
): HashManagerPasswordHasher {
    $config = new HashConfig(new FakeConfigRepository([
        'hashing.default' => $driver,
        'hashing.hashers.bcrypt.cost' => $bcryptCost,
        'hashing.hashers.argon2id.memory' => 1024,
        'hashing.hashers.argon2id.time' => 1,
        'hashing.hashers.argon2id.threads' => 1,
    ]));

    return new HashManagerPasswordHasher(new HashManager($config, new HasherFactory($config)));
}

it('implements PasswordHasherInterface', function (): void {
    expect(hashManagerPasswordHasher())->toBeInstanceOf(PasswordHasherInterface::class);
});

it('hashes and verifies with the configured driver', function (string $driver, string $prefix): void {
    $hasher = hashManagerPasswordHasher(driver: $driver);

    $hash = $hasher->hash('secret');

    expect($hash)->toStartWith($prefix)
        ->and($hasher->verify('secret', $hash))->toBeTrue()
        ->and($hasher->verify('wrong', $hash))->toBeFalse()
        ->and($hasher->needsRehash($hash))->toBeFalse();
})->with([
    'bcrypt' => ['bcrypt', '$2y$04$'],
    'argon2id' => ['argon2id', '$argon2id$'],
]);

it('reports a hash made at an older bcrypt cost as needing a rehash', function (): void {
    $oldHash = hashManagerPasswordHasher(bcryptCost: 4)->hash('secret');

    expect(hashManagerPasswordHasher(bcryptCost: 5)->needsRehash($oldHash))->toBeTrue();
});

it('verifies a bcrypt hash under the argon2id driver and reports it as needing a rehash', function (): void {
    $bcryptHash = password_hash('secret', PASSWORD_BCRYPT, ['cost' => 4]);
    $hasher = hashManagerPasswordHasher(driver: 'argon2id');

    expect($hasher->verify('secret', $bcryptHash))->toBeTrue()
        ->and($hasher->needsRehash($bcryptHash))->toBeTrue();
});

it('rejects a password bcrypt would truncate against a bcrypt hash under any driver', function (string $driver): void {
    $password = str_repeat('a', 72);
    $bcryptHash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 4]);
    $hasher = hashManagerPasswordHasher(driver: $driver);

    expect($hasher->verify($password . 'anything', $bcryptHash))->toBeFalse()
        ->and($hasher->verify("a\0b", password_hash('a', PASSWORD_BCRYPT, ['cost' => 4])))->toBeFalse()
        ->and($hasher->verify($password, $bcryptHash))->toBeTrue();
})->with(['bcrypt', 'argon2id']);

it('rejects a too-long password at hash time under the bcrypt driver', function (): void {
    hashManagerPasswordHasher()->hash(str_repeat('a', 73));
})->throws(InvalidPasswordException::class, 'Password is longer than 72 bytes');

it('rejects a NUL byte at hash time under the bcrypt driver', function (): void {
    hashManagerPasswordHasher()->hash("a\0b");
})->throws(InvalidPasswordException::class, 'Password contains a NUL byte');

it('hashes passwords over 72 bytes under the argon2id driver', function (): void {
    $password = str_repeat('a', 100);
    $hasher = hashManagerPasswordHasher(driver: 'argon2id');

    $hash = $hasher->hash($password);

    expect($hasher->verify($password, $hash))->toBeTrue()
        ->and($hasher->verify(str_repeat('a', 99) . 'b', $hash))->toBeFalse();
});

it('runs dummy verifications against a hash from the configured driver', function (string $driver): void {
    $hasher = hashManagerPasswordHasher(driver: $driver);

    $hasher->verifyDummy('first');
    $hasher->verifyDummy('second');

    $dummyHash = new ReflectionProperty(HashManagerPasswordHasher::class, 'dummyHash')->getValue($hasher);

    expect($dummyHash)->toBeString()
        ->and($hasher->needsRehash($dummyHash))->toBeFalse()
        ->and(password_verify('second', $dummyHash))->toBeFalse();
})->with(['bcrypt', 'argon2id']);
