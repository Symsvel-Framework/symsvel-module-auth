<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Token;

use Doctrine\DBAL\Connection;

/**
 * Dedicated reset-token persistence. Atomic conditional UPDATE ensures that
 * only one concurrent request can consume a particular secret.
 */
final readonly class DbalPasswordResetStore
{
    public function __construct(private Connection $connection)
    {
    }

    public function save(TokenSubject $subject, PasswordResetToken $token, \DateTimeImmutable $now): void
    {
        if ($subject->context !== $token->context) {
            throw new \InvalidArgumentException('Password reset context mismatch.');
        }

        $this->connection->insert('symsvel_auth_password_reset_tokens', [
            'context' => $subject->context,
            'principal_id' => $subject->id,
            'token_hash' => $token->hash,
            'expires_at' => self::timestamp($token->expiresAt),
            'created_at' => self::timestamp($now),
        ]);
    }

    /**
     * Returns the principal ID only for a newly consumed, unexpired token
     * belonging to the requested context. Call within the password-update
     * transaction so consumption rolls back if the password update fails.
     */
    public function consume(string $context, string $raw, \DateTimeImmutable $now): ?int
    {
        if (!in_array($context, ['bo', 'app'], true)) {
            return null;
        }
        $hash = PasswordResetToken::fingerprint($raw);
        if ($hash === null) {
            return null;
        }

        return $this->connection->transactional(function () use ($context, $hash, $now): ?int {
            $row = $this->connection->fetchAssociative(
                'SELECT principal_id FROM symsvel_auth_password_reset_tokens WHERE context = ? AND token_hash = ? AND used_at IS NULL AND expires_at > ?',
                [$context, $hash, self::timestamp($now)],
            );
            if ($row === false) {
                return null;
            }
            $changed = $this->connection->executeStatement(
                'UPDATE symsvel_auth_password_reset_tokens SET used_at = ? WHERE context = ? AND token_hash = ? AND used_at IS NULL AND expires_at > ?',
                [self::timestamp($now), $context, $hash, self::timestamp($now)],
            );
            return $changed === 1 ? (int) $row['principal_id'] : null;
        });
    }

    private static function timestamp(\DateTimeImmutable $date): string
    {
        return $date->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d H:i:s.u');
    }
}
