<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Token;

/**
 * Invalidates every session of one BO or App principal.
 * Suitable after password reset, account disablement or security incidents.
 * The caller is responsible for authorization and principal status checks.
 */
final readonly class TokenSessionRevoker
{
    public function __construct(private TokenStore $store)
    {
    }

    public function revokeAll(TokenSubject $subject, \DateTimeImmutable $now): void
    {
        $this->store->transaction(fn () => $this->store->revokeSubject($subject, $now));
    }
}
