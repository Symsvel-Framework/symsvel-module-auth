<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Identity;

use Doctrine\DBAL\Connection;
use SymSvel\Module\Auth\Token\DbalAppInvitationStore;

/** Single transaction for token consumption and first password/email verification. */
final readonly class AppInvitationCompletion
{
    public function __construct(
        private Connection $connection,
        private DbalAppInvitationStore $invitations,
        private AppInvitationOwners $users,
    ) {}

    public function complete(string $rawToken, string $password, \DateTimeImmutable $now): bool
    {
        if (!NewPasswordPolicy::accepts($password)) {
            return false;
        }

        try {
            return $this->connection->transactional(function () use ($rawToken, $password, $now): bool {
                $record = $this->invitations->consume($rawToken, $now);
                if ($record === null) return false;
                $hash = password_hash($password, PASSWORD_ARGON2ID);
                if (!$this->users->activate($record['userId'], $record['emailHash'], $hash, $now)) {
                    throw new AppInvitationUnavailable();
                }
                return true;
            });
        } catch (AppInvitationUnavailable) {
            return false;
        }
    }
}
