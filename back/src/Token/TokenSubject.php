<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Token;

/**
 * Identité stable, distincte des rôles et permissions.
 */
final readonly class TokenSubject
{
    public function __construct(public string $context, public int $id)
    {
        if (!in_array($context, ['bo', 'app'], true) || $id < 1) {
            throw new \InvalidArgumentException('Invalid authentication subject.');
        }
    }
}
