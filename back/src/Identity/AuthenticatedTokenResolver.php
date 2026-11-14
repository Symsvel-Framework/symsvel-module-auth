<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Identity;

use SymSvel\Module\Auth\Token\AccessTokenVerifier;
use SymSvel\Module\Auth\Token\TokenSubject;

/**
 * Verifies both the opaque token and the current account status.
 * Never treats a valid token as proof that an account still exists.
 */
final readonly class AuthenticatedTokenResolver
{
    public function __construct(
        private AccessTokenVerifier $tokens,
        private PrincipalStatus $principals,
    ) {
    }

    public function resolve(string $rawAccess, string $context, \DateTimeImmutable $now): ?TokenSubject
    {
        $subject = $this->tokens->verify($rawAccess, $context, $now);
        if ($subject === null || !$this->principals->isActive($subject)) {
            return null;
        }

        return $subject;
    }
}
