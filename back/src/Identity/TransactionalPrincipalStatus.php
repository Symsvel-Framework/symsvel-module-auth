<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Identity;

use SymSvel\Module\Auth\Token\TokenSubject;

/** Optional identity-owner guard: current row is locked in the Auth transaction. */
interface TransactionalPrincipalStatus extends PrincipalStatus
{
    public function lockActive(TokenSubject $subject): bool;
}
