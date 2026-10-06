<?php

declare(strict_types=1);

namespace Marko\Authentication\Exceptions;

class InvalidPasswordException extends AuthException
{
    public static function tooLong(
        int $maxBytes,
        int $actualBytes,
    ): self {
        return new self(
            message: "Password is longer than $maxBytes bytes",
            context: "Bcrypt only uses the first $maxBytes bytes of a password; got $actualBytes bytes. Hashing it would silently ignore the rest",
            suggestion: "Validate that passwords are at most $maxBytes bytes (strlen(), not mb_strlen()) on registration and password change, before calling PasswordHasherInterface::hash()",
        );
    }

    public static function containsNulByte(): self
    {
        return new self(
            message: 'Password contains a NUL byte',
            context: 'Bcrypt cannot hash a password containing a NUL (\0) byte',
            suggestion: 'Reject passwords containing NUL bytes during validation, before calling PasswordHasherInterface::hash()',
        );
    }
}
