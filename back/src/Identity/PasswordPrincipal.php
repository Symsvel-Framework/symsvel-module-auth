<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Identity;

use SymSvel\Module\Auth\Token\TokenSubject;

/**
 * Verified identity returned by the owning Admins/Users module.
 * Password verification and account-state checks belong to that module.
 */
interface PasswordPrincipal
{
    public function authenticate(string $context, string $identifier, string $password): ?TokenSubject;
}
