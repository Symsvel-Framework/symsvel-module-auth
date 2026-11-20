<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Identity;

use SymSvel\Module\Auth\Token\TokenSubject;

/** Account ownership remains in Admins (BO) or Users (App), not in Auth. */
interface ProfileEmailOwner
{
    public function authContext(): string;

    /**
     * Replace only the active principal's existing, unchanged mailbox.
     * Called within the shared Auth DBAL transaction.
     */
    public function confirmNewEmail(
        TokenSubject $subject,
        string $oldEmailHash,
        string $newEmail,
        \DateTimeImmutable $now,
    ): bool;
}
