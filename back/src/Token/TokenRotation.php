<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Token;

use SymSvel\Module\Auth\Identity\PrincipalStatus;

/**
 * Orchestre la rotation dans une transaction de TokenStore.
 * Aucune émission de token ne doit être exposée avant le commit.
 */
final readonly class TokenRotation
{
    public function __construct(
        private TokenStore $store,
        private TokenFactory $factory,
        private RefreshTokenGuard $guard,
        private PrincipalStatus $principals,
    ) {
    }

    public function rotate(string $rawRefresh, string $context, \DateTimeImmutable $now): RefreshResult
    {
        if (!in_array($context, ['bo', 'app'], true) || !preg_match('/^[A-Za-z0-9_-]{43}$/D', $rawRefresh)) {
            return new RefreshResult(RefreshDecision::Reject);
        }

        return $this->store->transaction(function () use ($rawRefresh, $context, $now): RefreshResult {
            $hash = hash('sha256', $rawRefresh);
            $record = $this->store->lockRefresh($hash);
            if ($record === null) {
                return new RefreshResult(RefreshDecision::Reject);
            }

            $decision = $this->guard->decide($record->state, $context, $now);
            if ($decision === RefreshDecision::RevokeFamily) {
                $this->store->revokeFamily($context, $record->state->familyId, $now);

                return new RefreshResult(RefreshDecision::RevokeFamily);
            }
            if ($decision !== RefreshDecision::Rotate) {
                return new RefreshResult(RefreshDecision::Reject);
            }

            if (!$this->principals->isActive($record->subject)) {
                // An inactive or deleted principal must not renew a session.
                $this->store->revokeFamily($context, $record->state->familyId, $now);

                return new RefreshResult(RefreshDecision::Reject);
            }

            if (!$this->store->consumeRefresh($hash, $now)) {
                // Une consommation concurrente a gagné. Le stockage doit
                // garantir que cette révocation est sérialisée après elle.
                $this->store->revokeFamily($context, $record->state->familyId, $now);

                return new RefreshResult(RefreshDecision::RevokeFamily);
            }

            $this->store->revokeFamilyAccess($context, $record->state->familyId, $now);
            $pair = $this->factory->issue($context, $record->state->familyId, $now);
            $this->store->savePair($record->subject, $pair, $now);

            return new RefreshResult(RefreshDecision::Rotate, $pair);
        });
    }
}
