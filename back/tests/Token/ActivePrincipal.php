<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Token;

use SymSvel\Module\Auth\Identity\PrincipalStatus;
use SymSvel\Module\Auth\Token\TokenSubject;

/** Explicit test double: production requires a real identity provider. */
final class ActivePrincipal implements PrincipalStatus
{
    public bool $active = true;

    public function isActive(TokenSubject $subject): bool
    {
        return $this->active;
    }
}
