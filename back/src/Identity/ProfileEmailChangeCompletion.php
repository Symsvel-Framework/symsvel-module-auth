<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Identity;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
use SymSvel\Module\Auth\Token\DbalProfileEmailChangeStore;
use SymSvel\Module\Auth\Token\DbalTokenStore;

/** Consume the single-use link, change the mailbox and revoke sessions atomically. */
final readonly class ProfileEmailChangeCompletion
{
    public function __construct(
        private Connection $db,
        private DbalProfileEmailChangeStore $tokens,
        private ContextProfileEmailOwners $owners,
        private DbalTokenStore $sessions,
    ) {
    }

    public function complete(string $context, string $rawToken, \DateTimeImmutable $now): bool
    {
        if (!in_array($context, ['bo', 'app'], true)) {
            return false;
        }
        try {
            return $this->db->transactional(function () use ($context, $rawToken, $now): bool {
                $change = $this->tokens->consume($context, $rawToken, $now);
                if ($change === null) {
                    return false;
                }
                if (!$this->owners->confirm(
                    $change['subject'], $change['oldEmailHash'], $change['newEmail'], $now,
                )) {
                    throw new ProfileEmailChangeUnavailable();
                }
                $this->sessions->revokeSubject($change['subject'], $now);

                return true;
            });
        } catch (ProfileEmailChangeUnavailable | UniqueConstraintViolationException) {
            return false;
        }
    }
}
