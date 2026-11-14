<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Identity;

use SymSvel\Module\Auth\Token\TokenSubject;

/**
 * Contract supplied by the owner of the BO/App identity.
 * Auth must not depend on Admins or Users implementations.
 */
interface PrincipalStatus
{
    public function isActive(TokenSubject $subject): bool;
}
