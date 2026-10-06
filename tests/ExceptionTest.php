<?php

declare(strict_types=1);

use Marko\Authentication\Exceptions\AuthenticationException;
use Marko\Authentication\Exceptions\AuthException;
use Marko\Authentication\Exceptions\InvalidCredentialsException;

it('creates AuthException as base exception', function () {
    $exception = new AuthException('Authentication failed');

    expect($exception)->toBeInstanceOf(Exception::class)
        ->and($exception->getMessage())->toBe('Authentication failed');
});

it('creates AuthException with context and suggestion', function () {
    $exception = new AuthException(
        message: 'Authentication failed',
        context: 'User attempted login with invalid token',
        suggestion: 'Please provide valid credentials',
    );

    expect($exception->getContext())->toBe('User attempted login with invalid token')
        ->and($exception->getSuggestion())->toBe('Please provide valid credentials');
});

it('creates AuthenticationException extending AuthException', function () {
    $exception = new AuthenticationException('User not authenticated');

    expect($exception)->toBeInstanceOf(AuthException::class)
        ->and($exception->getMessage())->toBe('User not authenticated');
});

it('creates AuthenticationException with factory method', function () {
    $exception = AuthenticationException::unauthenticated('web');

    expect($exception)->toBeInstanceOf(AuthenticationException::class)
        ->and($exception->getMessage())->toBe('Unauthenticated')
        ->and($exception->getContext())->toContain('web')
        ->and($exception->getSuggestion())->not->toBeEmpty();
});

it('no longer ships a duplicate AuthorizationException in the authentication package', function () {
    expect(class_exists('Marko\\Authentication\\Exceptions\\AuthorizationException'))->toBeFalse();
});

it('creates InvalidCredentialsException extending AuthenticationException', function () {
    $exception = new InvalidCredentialsException('Invalid credentials');

    expect($exception)->toBeInstanceOf(AuthenticationException::class)
        ->toBeInstanceOf(AuthException::class)
        ->and($exception->getMessage())->toBe('Invalid credentials');
});

it('creates InvalidCredentialsException with default message', function () {
    $exception = InvalidCredentialsException::invalidCredentials();

    expect($exception)->toBeInstanceOf(InvalidCredentialsException::class)
        ->and($exception->getMessage())->toBe('Invalid credentials')
        ->and($exception->getContext())->not->toBeEmpty()
        ->and($exception->getSuggestion())->not->toBeEmpty();
});
