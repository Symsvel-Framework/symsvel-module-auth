<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Token;

/**
 * Instantané de l'état persistant d'un refresh token.
 * L'appelant doit garantir le verrouillage transactionnel avant de l'évaluer.
 */
final readonly class RefreshTokenState
{
    public function __construct(
        public string $context,
        public string $familyId,
        public \DateTimeImmutable $expiresAt,
        public ?\DateTimeImmutable $usedAt = null,
        public ?\DateTimeImmutable $revokedAt = null,
    ) {
    }
}
