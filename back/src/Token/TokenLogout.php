<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Token;

/**
 * Revokes a complete token family using its refresh secret.
 * Does not authenticate a principal or expose an HTTP endpoint.
 */
final readonly class TokenLogout
{
    public function __construct(private TokenStore $store)
    {
    }

    public function logout(string $rawRefresh, string $context, \DateTimeImmutable $now): bool
    {
        if (!in_array($context, ['bo', 'app'], true) || !preg_match('/^[A-Za-z0-9_-]{43}$/D', $rawRefresh)) {
            return false;
        }

        return $this->store->transaction(function () use ($rawRefresh, $context, $now): bool {
            $record = $this->store->lockRefresh(hash('sha256', $rawRefresh));
            if ($record === null || $record->state->context !== $context || $record->state->revokedAt !== null) {
                return false;
            }

            $this->store->revokeFamily($context, $record->state->familyId, $now);

            return true;
        });
    }
}
