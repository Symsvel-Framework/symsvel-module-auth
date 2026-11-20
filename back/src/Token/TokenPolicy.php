<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Token;

/**
 * Durées issues de XCore. La politique peut être remplacée par configuration
 * lors de l'intégration Symfony, sans changer le format des tokens.
 */
final readonly class TokenPolicy
{
    public function __construct(
        public int $accessTtl = 900,
        public int $refreshTtl = 2592000,
    ) {
        if ($accessTtl < 1 || $refreshTtl < 1 || $refreshTtl <= $accessTtl) {
            throw new \InvalidArgumentException('Invalid token lifetimes.');
        }
    }
}
