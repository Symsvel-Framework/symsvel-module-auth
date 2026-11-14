<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Token;

final readonly class IssuedToken
{
    public function __construct(
        public string $raw,
        public string $hash,
        public \DateTimeImmutable $expiresAt,
    ) {
    }
}
