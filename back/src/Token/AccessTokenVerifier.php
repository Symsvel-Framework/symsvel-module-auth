<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Token;

/**
 * Validates an opaque access token, its expiry and its BO/App scope.
 * Account status must be checked by the caller before authentication.
 */
final readonly class AccessTokenVerifier
{
    public function __construct(private AccessTokenLookup $lookup)
    {
    }

    public function verify(string $raw, string $context, \DateTimeImmutable $now): ?TokenSubject
    {
        if (!in_array($context, ['bo', 'app'], true) || !preg_match('/^[A-Za-z0-9_-]{43}$/D', $raw)) {
            return null;
        }

        $record = $this->lookup->findAccessByHash(hash('sha256', $raw));
        if ($record === null || $record->subject->context !== $context || $record->revokedAt !== null || $record->expiresAt <= $now) {
            return null;
        }

        return $record->subject;
    }
}
