<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Token;

use Doctrine\DBAL\Connection;

/** Opaque, single-use invitation tokens stored separately from BO and reset tokens. */
final readonly class DbalAppInvitationStore
{
    public function __construct(private Connection $connection) {}

    public function save(int $userId, string $email, AppInvitationToken $token, \DateTimeImmutable $now): void
    {
        $email = strtolower(trim($email));
        if ($userId < 1 || strlen($email) > 254 || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            throw new \InvalidArgumentException('Invalid App invitation.');
        }
        $this->connection->insert('symsvel_auth_app_invitations', [
            'principal_id' => $userId,
            'email_hash' => hash('sha256', $email),
            'token_hash' => $token->hash,
            'expires_at' => self::timestamp($token->expiresAt),
            'created_at' => self::timestamp($now),
        ]);
    }

    /** @return array{userId: int, emailHash: string}|null */
    public function consume(string $raw, \DateTimeImmutable $now): ?array
    {
        $hash = AppInvitationToken::fingerprint($raw);
        if ($hash === null) return null;
        return $this->connection->transactional(function () use ($hash, $now): ?array {
            $count = $this->connection->executeStatement(
                'UPDATE symsvel_auth_app_invitations SET used_at = ? WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?',
                [self::timestamp($now), $hash, self::timestamp($now)],
            );
            if ($count !== 1) return null;
            $row = $this->connection->fetchAssociative(
                'SELECT principal_id, email_hash FROM symsvel_auth_app_invitations WHERE token_hash = ?',
                [$hash],
            );
            if ($row === false) {
                throw new \LogicException('Consumed App invitation token disappeared.');
            }
            return ['userId' => (int) $row['principal_id'], 'emailHash' => (string) $row['email_hash']];
        });
    }

    private static function timestamp(\DateTimeImmutable $when): string
    {
        return $when->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d H:i:s.u');
    }

