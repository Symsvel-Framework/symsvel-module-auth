<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Identity;

use Doctrine\DBAL\Connection;
use SymSvel\Module\Auth\Token\DbalAdminInvitationStore;

/** Consumes an invitation and activates its BO account in the same DBAL transaction. */
final readonly class AdminInvitationCompletion
{
    public function __construct(
        private Connection $connection,
        private DbalAdminInvitationStore $invitations,
        private AdminInvitationIdentity $admins,
    ) {
    }

    public function complete(string $rawToken, string $password, \DateTimeImmutable $now): bool
    {
        if (strlen($password) < 12 || strlen($password) > 1024 || str_contains($password, "\0")) {
            return false;
        }

        try {
            return $this->connection->transactional(function () use ($rawToken, $password, $now): bool {
                $record = $this->invitations->consume($rawToken, $now);
                if ($record === null) {
                    return false;
                }
                $hash = password_hash($password, PASSWORD_ARGON2ID);
                if (!$this->admins->activateInvitation($record['adminId'], $record['emailHash'], $hash, $now)) {
                    throw new AdminInvitationUnavailable();
                }

                return true;
            });
        } catch (AdminInvitationUnavailable) {
            return false;
        }
    }
}
