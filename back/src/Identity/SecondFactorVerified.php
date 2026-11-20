<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Identity;

use SymSvel\Module\Auth\Token\TokenPair;

/** Optional result of a verified second factor, using Auth's original tokens. */
final readonly class SecondFactorVerified
{
    /** @param list<string> $recoveryCodes */
    public function __construct(public TokenPair $tokens, public array $recoveryCodes = [])
    {
    }
}
