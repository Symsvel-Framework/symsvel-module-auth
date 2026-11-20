<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Token;

use Doctrine\DBAL\Connection;

/**
 * Email verification only. Consume inside the account owner's DBAL transaction
 * so a failed confirmation can roll back token consumption.
 */
final readonly class DbalEmailVerificationStore
{
    public function __construct(private Connection $connection)
    {
    }

    public function save(
        TokenSubject $subject,
        string $email,
        EmailVerificationToken $token,
        \DateTimeImmutable $now,
    ): void {
        $email = strtolower(trim($email));
        if ($subject->context !== $token->context
            || strlen($email) > 254
            || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            throw new \InvalidArgumentException('Invalid email verification request.');
        }

        $this->connection->insert('symsvel_auth_email_verification_tokens', [
            'context' => $subject->context,
            'principal_id' => $subject->id,
            'email_hash' => hash('sha256', $email),
            'token_hash' => $token->hash,
            'expires_at' => self::timestamp($token->expiresAt),
            'created_at' => self::timestamp($now),
        ]);
    }

    /** @return array{subject: TokenSubject, emailHash: string}|null */
    public function consume(string $context, string $raw, \DateTimeImmutable $now): ?array
    {
        if (!in_array($context, ['bo', 'app'], true)) {
            return null;
        }
        $hash = EmailVerificationToken::fingerprint($raw);
        if ($hash === null) {
            return null;
        }

        return $this->connection->transactional(function () use ($context, $hash, $now): ?array {
            $changed = $this->connection->executeStatement(
                'UPDATE symsvel_auth_email_verification_tokens SET used_at = ? WHERE context = ? AND token_hash = ? AND used_at IS NULL AND expires_at > ?',
                [self::timestamp($now), $context, $hash, self::timestamp($now)],
            );
            if ($changed !== 1) {
                return null;
            }

            $row = $this->connection->fetchAssociative(
                'SELECT principal_id, email_hash FROM symsvel_auth_email_verification_tokens WHERE context = ? AND token_hash = ?',
                [$context, $hash],
            );
            if ($row === false) {
                throw new \LogicException('Consumed email verification token disappeared inside transaction.');
            }

            return [
                'subject' => new TokenSubject($context, (int) $row['principal_id']),
                'emailHash' => (string) $row['email_hash'],
            ];
        });
    }

    private static function timestamp(\DateTimeImmutable $date): string
    {
        return $date->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d H:i:s.u');
    }
}
