<?php

declare(strict_types=1);

function authenticationReadme(): string
{
    return file_get_contents(dirname(__DIR__) . '/README.md');
}

it('README exists in package root', function () {
    expect(file_exists(dirname(__DIR__) . '/README.md'))->toBeTrue();
});

it('README starts with the package title', function () {
    expect(authenticationReadme())->toStartWith('# marko/authentication');
});

it('README includes installation instructions', function () {
    expect(authenticationReadme())->toContain('## Installation')
        ->toContain('composer require marko/authentication');
});

it('README includes a quick example', function () {
    expect(authenticationReadme())->toContain('## Quick Example')
        ->toContain('AuthManager')
        ->toContain('attempt(');
});

it('README links to the full documentation', function () {
    expect(authenticationReadme())->toContain('https://marko.build/docs/packages/authentication/');
});
