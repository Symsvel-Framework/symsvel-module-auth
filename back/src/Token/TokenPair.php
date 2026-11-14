<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Token;

final readonly class TokenPair
{
    public function __construct(
        public string $context,
        public string $familyId,
        public IssuedToken $access,
        public IssuedToken $refresh,
    ) {
    }
}
