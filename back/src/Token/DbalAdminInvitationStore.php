<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Token;

use Doctrine\DBAL\Connection;

/**
 * BO-only administrator invitations. Call consume inside the account activation
 * transaction so failed password creation rolls back token consumption.
 */
final readonly class DbalAdminInvitationStore
{
    public function __construct(private Connection $connection)
    {
    }

    public function save(int $adminId, string $email, AdminInvitationToken $token, \DateTimeImmutable $now): void
    {
        $email = strtolower(trim($email));
        if ($adminId < 1 || strlen($email) > 254 || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            throw new \InvalidArgumentException('Invalid administrator invitation.');
        }

        $this->connection->insert('symsvel_auth_admin_invitations', [
            'principal_id' => $adminId,
            'email_hash' => hash('sha256', $email),
            'token_hash' => $token->hash,
            'expires_at' => self::timestamp($token->expiresAt),
            'created_at' => self::timestamp($now),
        ]);
    }

    /** @return array{adminId: int, emailHash: string}|null */
    public function consume(string $raw, \DateTimeImmutable $now): ?array
    {
        $hash = AdminInvitationToken::fingerprint($raw);
        if ($hash === null) {
            return null;
        }

        return $this->connection->transactional(function () use ($hash, $now): ?array {
            $changed = $this->connection->executeStatement(
                'UPDATE symsvel_auth_admin_invitations SET used_at = ? WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?',
                [self::timestamp($now), $hash, self::timestamp($now)],
            );
            if ($changed !== 1) {
                return null;
            }

            $row = $this->connection->fetchAssociative(
                'SELECT principal_id, email_hash FROM symsvel_auth_admin_invitations WHERE token_hash = ?',
                [$hash],
            );
            if ($row === false) {
                throw new \LogicException('Consumed administrator invitation disappeared inside transaction.');
            }

            return ['adminId' => (int) $row['principal_id'], 'emailHash' => (string) $row['email_hash']];
        });
    }

    private static function timestamp(\DateTimeImmutable $date): string
    {
        return $date->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d H:i:s.u');
    }
}
