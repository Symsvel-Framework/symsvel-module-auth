<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Token;

final readonly class AccessTokenRecord
{
    public function __construct(
        public TokenSubject $subject,
        public \DateTimeImmutable $expiresAt,
        public ?\DateTimeImmutable $revokedAt,
    ) {
    }
}
