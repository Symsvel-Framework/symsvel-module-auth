<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Identity;

use Doctrine\DBAL\Connection;
use SymSvel\Module\Auth\Token\DbalEmailVerificationStore;

/** Consumption and owner confirmation are one DBAL transaction. */
final readonly class EmailVerificationCompletion
{
    public function __construct(
        private Connection $connection,
        private DbalEmailVerificationStore $tokens,
        private ContextEmailVerificationIdentity $identities,
    ) {
    }

    public function complete(string $context, string $rawToken, \DateTimeImmutable $now): bool
    {
        if (!in_array($context, ['bo', 'app'], true)) {
            return false;
        }

        try {
            return $this->connection->transactional(function () use ($context, $rawToken, $now): bool {
                $record = $this->tokens->consume($context, $rawToken, $now);
                if ($record === null) {
                    return false;
                }
                if (!$this->identities->confirm($record['subject'], $record['emailHash'], $now)) {
                    throw new EmailVerificationUnavailable();
                }

                return true;
            });
        } catch (EmailVerificationUnavailable) {
            return false;
        }
    }
}
