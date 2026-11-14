<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Token;

final readonly class RefreshTokenRecord
{
    public function __construct(
        public TokenSubject $subject,
        public RefreshTokenState $state,
    ) {
        if ($subject->context !== $state->context) {
            throw new \InvalidArgumentException('Refresh token context mismatch.');
        }
    }
}
