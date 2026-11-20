<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Token;

/**
 * Politique pure : ne remplace ni le verrouillage BDD ni la transaction.
 */
final class RefreshTokenGuard
{
    public function decide(RefreshTokenState $state, string $requestedContext, \DateTimeImmutable $now): RefreshDecision
    {
        if (!in_array($requestedContext, ['bo', 'app'], true) || $state->context !== $requestedContext) {
            return RefreshDecision::Reject;
        }

        if ($state->usedAt !== null) {
            return RefreshDecision::RevokeFamily;
        }

        if ($state->revokedAt !== null) {
            return RefreshDecision::Reject;
        }

        if ($state->expiresAt <= $now) {
            return RefreshDecision::Reject;
        }

        return RefreshDecision::Rotate;
    }
}
