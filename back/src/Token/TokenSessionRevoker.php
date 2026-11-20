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
        $this->revokeWith($subject, $now, static fn () => null);
    }

    /**
     * Run a module-owned account mutation and session revocation in a single
     * TokenStore transaction. Callers must not open an outer DBAL transaction:
     * SQLite token storage deliberately requires the outermost writer lock.
     * The operation must use the same DBAL connection as the token store.
     */
    public function revokeWith(TokenSubject $subject, \DateTimeImmutable $now, callable $operation): mixed
    {
        return $this->store->transaction(function () use ($subject, $now, $operation): mixed {
            $result = $operation();
            $this->store->revokeSubject($subject, $now);

            return $result;
        });
    }
}
