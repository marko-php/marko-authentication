<?php

declare(strict_types=1);

use Marko\Authentication\Contracts\PasswordHasherInterface;
use Marko\Authentication\Exceptions\AuthException;
use Marko\Authentication\Exceptions\InvalidPasswordException;
use Marko\Authentication\Hashing\BcryptPasswordHasher;

it('creates PasswordHasherInterface with hash method', function () {
    $interface = new ReflectionClass(PasswordHasherInterface::class);

    expect($interface->isInterface())->toBeTrue()
        ->and($interface->hasMethod('hash'))->toBeTrue();

    $method = $interface->getMethod('hash');
    expect($method->getNumberOfRequiredParameters())->toBe(1);

    $param = $method->getParameters()[0];
    expect($param->getName())->toBe('password')
        ->and($param->getType()->getName())->toBe('string')
        ->and($method->getReturnType()->getName())->toBe('string');
});

it('creates PasswordHasherInterface with verify method', function () {
    $interface = new ReflectionClass(PasswordHasherInterface::class);

    expect($interface->hasMethod('verify'))->toBeTrue();

    $method = $interface->getMethod('verify');
    expect($method->getNumberOfRequiredParameters())->toBe(2);

    $params = $method->getParameters();
    expect($params[0]->getName())->toBe('password')
        ->and($params[0]->getType()->getName())->toBe('string')
        ->and($params[1]->getName())->toBe('hash')
        ->and($params[1]->getType()->getName())->toBe('string')
        ->and($method->getReturnType()->getName())->toBe('bool');
});

it('creates PasswordHasherInterface with needsRehash method', function () {
    $interface = new ReflectionClass(PasswordHasherInterface::class);

    expect($interface->hasMethod('needsRehash'))->toBeTrue();

    $method = $interface->getMethod('needsRehash');
    expect($method->getNumberOfRequiredParameters())->toBe(1);

    $param = $method->getParameters()[0];
    expect($param->getName())->toBe('hash')
        ->and($param->getType()->getName())->toBe('string')
        ->and($method->getReturnType()->getName())->toBe('bool');
});

it('creates BcryptPasswordHasher implementing interface', function () {
    $hasher = new BcryptPasswordHasher(cost: 4);

    expect($hasher)->toBeInstanceOf(PasswordHasherInterface::class);
});

it('hashes password with bcrypt algorithm', function () {
    $hasher = new BcryptPasswordHasher(cost: 4);

    $hash = $hasher->hash('secret');

    expect($hash)->toStartWith('$2y$')
        ->and(strlen($hash))->toBe(60);
});

it('verifies correct password returns true', function () {
    $hasher = new BcryptPasswordHasher(cost: 4);

    $hash = $hasher->hash('secret');

    expect($hasher->verify('secret', $hash))->toBeTrue();
});

it('verifies incorrect password returns false', function () {
    $hasher = new BcryptPasswordHasher(cost: 4);

    $hash = $hasher->hash('secret');

    expect($hasher->verify('wrong-password', $hash))->toBeFalse();
});

it('detects when rehash is needed', function () {
    $lowCostHasher = new BcryptPasswordHasher(cost: 4);
    $highCostHasher = new BcryptPasswordHasher(cost: 6);

    $hash = $lowCostHasher->hash('secret');

    expect($highCostHasher->needsRehash($hash))->toBeTrue();
});

it('supports configurable cost parameter', function () {
    $hasher = new BcryptPasswordHasher(cost: 5);

    $hash = $hasher->hash('secret');

    expect($hash)->toStartWith('$2y$05$');
});

it('uses default cost of 12', function () {
    // Verify default cost constant (without slow hashing)
    expect(BcryptPasswordHasher::DEFAULT_COST)->toBe(12);
});

it('hashes password to non-readable format', function () {
    $hasher = new BcryptPasswordHasher(cost: 4);
    $password = 'my-secret-password';

    $hash = $hasher->hash($password);

    expect($hash)->not->toBe($password)
        ->and($hash)->not->toContain($password)
        ->and(strlen($hash))->toBe(60);
});

it('produces different hash for same password', function () {
    $hasher = new BcryptPasswordHasher(cost: 4);
    $password = 'same-password';

    $hash1 = $hasher->hash($password);
    $hash2 = $hasher->hash($password);

    expect($hash1)->not->toBe($hash2)
        ->and($hasher->verify($password, $hash1))->toBeTrue()
        ->and($hasher->verify($password, $hash2))->toBeTrue();
});

it('detects rehash needed for lower cost', function () {
    $lowCostHasher = new BcryptPasswordHasher(cost: 4);
    $higherCostHasher = new BcryptPasswordHasher(cost: 6);

    $hashWithLowCost = $lowCostHasher->hash('secret');

    expect($higherCostHasher->needsRehash($hashWithLowCost))->toBeTrue();
});

it('detects no rehash needed for same cost', function () {
    $hasher = new BcryptPasswordHasher(cost: 4);

    $hash = $hasher->hash('secret');

    expect($hasher->needsRehash($hash))->toBeFalse();
});

it('uses custom cost when provided', function () {
    $hasher = new BcryptPasswordHasher(cost: 5);

    $hash = $hasher->hash('secret');

    expect($hash)->toStartWith('$2y$05$');
});

it('validates minimum cost requirement', function () {
    $hasher = new BcryptPasswordHasher(cost: 3);

    expect(fn () => $hasher->hash('secret'))
        ->toThrow(ValueError::class);
});

it('creates PasswordHasherInterface with verifyDummy method', function () {
    $interface = new ReflectionClass(PasswordHasherInterface::class);

    expect($interface->hasMethod('verifyDummy'))->toBeTrue();

    $method = $interface->getMethod('verifyDummy');
    expect($method->getNumberOfRequiredParameters())->toBe(1);

    $param = $method->getParameters()[0];
    expect($param->getName())->toBe('password')
        ->and($param->getType()->getName())->toBe('string')
        ->and($method->getReturnType()->getName())->toBe('void');
});

it('verifies dummy passwords against a well-formed bcrypt hash of the configured cost', function () {
    $hasher = new BcryptPasswordHasher(cost: 5);
    $dummyHash = new ReflectionMethod($hasher, 'dummyHash')->invoke($hasher);

    $info = password_get_info($dummyHash);

    expect($info['algo'])->toBe(PASSWORD_BCRYPT)
        ->and($info['options']['cost'])->toBe(5)
        ->and(strlen($dummyHash))->toBe(60)
        ->and($hasher->needsRehash($dummyHash))->toBeFalse();
});

it('uses the default cost for the dummy hash when none is configured', function () {
    $hasher = new BcryptPasswordHasher();
    $dummyHash = new ReflectionMethod($hasher, 'dummyHash')->invoke($hasher);

    expect(password_get_info($dummyHash)['options']['cost'])->toBe(BcryptPasswordHasher::DEFAULT_COST);
});

it('spends real hashing work on a dummy verification', function () {
    $cheapHasher = new BcryptPasswordHasher(cost: 4);
    $realHash = $cheapHasher->hash('secret');
    $costlyHasher = new BcryptPasswordHasher(cost: 10);

    $start = hrtime(true);
    $costlyHasher->verifyDummy('attacker-guess');
    $dummyNs = hrtime(true) - $start;

    $start = hrtime(true);
    $cheapHasher->verify('attacker-guess', $realHash);
    $cheapNs = hrtime(true) - $start;

    // A cost-10 check runs 64x the rounds of a cost-4 check; a short-circuited dummy would be far faster
    expect($dummyNs)->toBeGreaterThan($cheapNs * 4);
});

it('rejects a password longer than 72 bytes instead of silently truncating it', function () {
    $hasher = new BcryptPasswordHasher(cost: 4);

    expect(fn () => $hasher->hash(str_repeat('a', 73)))
        ->toThrow(InvalidPasswordException::class, 'Password is longer than 72 bytes');
});

it('counts bytes rather than characters when enforcing the 72-byte limit', function () {
    $hasher = new BcryptPasswordHasher(cost: 4);

    // 37 two-byte characters = 74 bytes
    expect(fn () => $hasher->hash(str_repeat('é', 37)))
        ->toThrow(InvalidPasswordException::class);
});

it('rejects a password containing a NUL byte with a specific exception', function () {
    $hasher = new BcryptPasswordHasher(cost: 4);

    expect(fn () => $hasher->hash("secret\0suffix"))
        ->toThrow(InvalidPasswordException::class, 'Password contains a NUL byte');
});

it('accepts a password of exactly 72 bytes', function () {
    $hasher = new BcryptPasswordHasher(cost: 4);
    $password = str_repeat('a', 72);

    $hash = $hasher->hash($password);

    expect($hasher->verify($password, $hash))->toBeTrue();
});

it('returns false when verifying a password longer than 72 bytes', function () {
    $hasher = new BcryptPasswordHasher(cost: 4);
    $hash = $hasher->hash(str_repeat('a', 72));

    // bcrypt would otherwise ignore the 73rd byte and report a match
    expect($hasher->verify(str_repeat('a', 72) . 'Y', $hash))->toBeFalse();
});

it('returns false when verifying a password containing a NUL byte', function () {
    $hasher = new BcryptPasswordHasher(cost: 4);
    $hash = $hasher->hash('secret');

    expect($hasher->verify("secret\0", $hash))->toBeFalse();
});

it('does not throw when a dummy verification receives an unhashable password', function () {
    $hasher = new BcryptPasswordHasher(cost: 4);

    $hasher->verifyDummy(str_repeat('a', 100));
    $hasher->verifyDummy("secret\0suffix");

    expect(true)->toBeTrue();
});

it('spends real hashing work when rejecting an oversize password during verification', function () {
    $costlyHasher = new BcryptPasswordHasher(cost: 10);
    $cheapHasher = new BcryptPasswordHasher(cost: 4);
    $cheapHash = $cheapHasher->hash('secret');

    $start = hrtime(true);
    $costlyHasher->verify(str_repeat('a', 100), $cheapHash);
    $rejectedNs = hrtime(true) - $start;

    $start = hrtime(true);
    $cheapHasher->verify('attacker-guess', $cheapHash);
    $cheapNs = hrtime(true) - $start;

    // An instant false for a known account would contrast with verifyDummy's full-cost run for an unknown
    // one, letting response timing reveal which accounts exist
    expect($rejectedNs)->toBeGreaterThan($cheapNs * 4);
});

it('builds InvalidPasswordException with context and suggestion', function () {
    $tooLong = InvalidPasswordException::tooLong(72, 80);
    $nulByte = InvalidPasswordException::containsNulByte();

    expect($tooLong)->toBeInstanceOf(AuthException::class)
        ->and($tooLong->getMessage())->toBe('Password is longer than 72 bytes')
        ->and($tooLong->getContext())->toContain('80 bytes')
        ->and($tooLong->getSuggestion())->not->toBeEmpty()
        ->and($nulByte)->toBeInstanceOf(AuthException::class)
        ->and($nulByte->getMessage())->toBe('Password contains a NUL byte')
        ->and($nulByte->getContext())->not->toBeEmpty()
        ->and($nulByte->getSuggestion())->not->toBeEmpty();
});
