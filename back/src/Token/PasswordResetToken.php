<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Token;

/**
 * One-time password-reset secret material. Persistence and consumption belong
 * to a dedicated repository, never to the session token store.
 */
final readonly class PasswordResetToken
{
    public function __construct(
        public string $context,
        public string $raw,
        public string $hash,
        public \DateTimeImmutable $expiresAt,
    ) {
        if (!in_array($context, ['bo', 'app'], true)
            || !preg_match('/^[A-Za-z0-9_-]{43}$/D', $raw)
            || !hash_equals(hash('sha256', $raw), $hash)) {
            throw new \InvalidArgumentException('Invalid password reset token.');
        }
    }

    public static function issue(string $context, \DateTimeImmutable $now, int $ttlSeconds = 1800): self
    {
        if (!in_array($context, ['bo', 'app'], true) || $ttlSeconds < 1) {
            throw new \InvalidArgumentException('Invalid password reset policy.');
        }

        $raw = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');

        return new self($context, $raw, hash('sha256', $raw), $now->modify('+'.$ttlSeconds.' seconds'));
    }

    public static function fingerprint(string $raw): ?string
    {
        return preg_match('/^[A-Za-z0-9_-]{43}$/D', $raw) ? hash('sha256', $raw) : null;
    }
}
