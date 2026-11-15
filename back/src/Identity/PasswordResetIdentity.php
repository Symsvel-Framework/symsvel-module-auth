<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Identity;

use SymSvel\Module\Auth\Token\TokenSubject;

/**
 * Credential ownership remains with Admins (bo) or Users (app).
 * Implementations must persist through the host DBAL transaction.
 */
interface PasswordResetIdentity extends ContextOwnedIdentity
{
    public function findResetSubject(string $identifier): ?TokenSubject;

    public function replacePassword(TokenSubject $subject, string $newPasswordHash): bool;
}
