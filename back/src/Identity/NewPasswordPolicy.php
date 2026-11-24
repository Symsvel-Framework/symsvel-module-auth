<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Identity;

/** Policy for assigning a new password only; never apply to existing credentials at login. */
final class NewPasswordPolicy
{
    public static function accepts(#[\SensitiveParameter] string $password): bool
    {
        return strlen($password) <= 1024
            && !str_contains($password, "\0")
            && preg_match_all('/./us', $password) >= 12
            && preg_match('/\p{Lu}/u', $password) === 1
            && preg_match('/\p{Ll}/u', $password) === 1
            && preg_match('/\p{Nd}/u', $password) === 1
            && preg_match('/[\p{P}\p{S}]/u', $password) === 1;
    }
}
