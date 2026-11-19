<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Token;

use Doctrine\DBAL\Connection;

/**
 * Pending email change: the old verified address remains active until completion.
 * Only a SHA-256 fingerprint of the opaque one-time token is persisted.
 */
final readonly class DbalProfileEmailChangeStore
{
    public function __construct(private Connection $db)
    {
    }

    public function save(
        TokenSubject $subject,
        string $oldEmail,
        string $newEmail,
        EmailVerificationToken $token,
        \DateTimeImmutable $now,
    ): void {
        $old = strtolower(trim($oldEmail));
        $new = strtolower(trim($newEmail));
        if ($token->context !== $subject->context || $old === $new
            || filter_var($old, FILTER_VALIDATE_EMAIL) === false
            || filter_var($new, FILTER_VALIDATE_EMAIL) === false
            || strlen($new) > 254) {
            throw new \InvalidArgumentException('Invalid email change request.');
        }
        $this->db->insert('symsvel_auth_profile_email_changes', [
            'context' => $subject->context,
            'principal_id' => $subject->id,
            'old_email_hash' => hash('sha256', $old),
            'new_email' => $new,
            'token_hash' => $token->hash,
            'expires_at' => self::timestamp($token->expiresAt),
            'created_at' => self::timestamp($now),
        ]);
    }

    /**
     * Must be called inside the completion transaction.
     *
     * @return array{subject: TokenSubject, oldEmailHash: string, newEmail: string}|null
     */
    public function consume(string $context, string $rawToken, \DateTimeImmutable $now): ?array
    {
        if (!in_array($context, ['bo', 'app'], true)) {
            return null;
        }
        $hash = EmailVerificationToken::fingerprint($rawToken);
        if ($hash === null) {
            return null;
        }
        $updated = $this->db->executeStatement(
            'UPDATE symsvel_auth_profile_email_changes SET used_at = ?'
            .' WHERE context = ? AND token_hash = ? AND used_at IS NULL AND expires_at > ?',
            [self::timestamp($now), $context, $hash, self::timestamp($now)],
        );
        if ($updated !== 1) {
            return null;
        }
        $row = $this->db->fetchAssociative(
            'SELECT principal_id, old_email_hash, new_email FROM symsvel_auth_profile_email_changes'
            .' WHERE context = ? AND token_hash = ?',
            [$context, $hash],
        );
        if ($row === false) {
            throw new \LogicException('Consumed email change token disappeared within transaction.');
        }
        return [
            'subject' => new TokenSubject($context, (int) $row['principal_id']),
            'oldEmailHash' => (string) $row['old_email_hash'],
            'newEmail' => (string) $row['new_email'],
        ];
    }

    private static function timestamp(\DateTimeImmutable $date): string
    {
        return $date->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d H:i:s.u');
    }
}
