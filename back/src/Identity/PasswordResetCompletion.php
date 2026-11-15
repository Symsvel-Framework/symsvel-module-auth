<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Identity;

use Doctrine\DBAL\Connection;
use SymSvel\Module\Auth\Token\DbalPasswordResetStore;
use SymSvel\Module\Auth\Token\DbalTokenStore;
use SymSvel\Module\Auth\Token\TokenSubject;

/**
 * Completes a password reset in one DBAL transaction shared with account owners.
 * No HTTP or mail side effects occur within the transaction.
 */
final readonly class PasswordResetCompletion
{
    public function __construct(
        private Connection $connection,
        private DbalPasswordResetStore $resets,
        private ContextPasswordResetIdentity $identities,
        private DbalTokenStore $sessions,
    ) {
    }

    public function complete(string $context, string $rawToken, string $newPassword, \DateTimeImmutable $now): bool
    {
        if (!in_array($context, ['bo', 'app'], true) || strlen($newPassword) < 12 || strlen($newPassword) > 1024) {
            return false;
        }

        $hash = password_hash($newPassword, PASSWORD_ARGON2ID);

        try {
            return $this->connection->transactional(function () use ($context, $rawToken, $hash, $now): bool {
                $id = $this->resets->consume($context, $rawToken, $now);
                if ($id === null) {
                    return false;
                }

                $subject = new TokenSubject($context, $id);
                if (!$this->identities->replace($subject, $hash)) {
                    // Do not consume a token when the owning account cannot be updated.
                    throw new PasswordResetAccountUnavailable();
                }

                $this->sessions->revokeSubject($subject, $now);

                return true;
            });
        } catch (PasswordResetAccountUnavailable) {
            return false;
        }
    }
}
