<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Identity;

/** Unauthenticated, short-lived challenge: never a session or an access token. */
final readonly class SecondFactorChallenge
{
    public function __construct(
        public string $challenge,
        public \DateTimeImmutable $expiresAt,
        public bool $enrollmentRequired = false,
        public ?string $totpSecret = null,
        public ?string $provisioningUri = null,
    ) {
        if (!preg_match('/^[A-Za-z0-9_-]{43}$/D', $challenge)) {
            throw new \InvalidArgumentException('Invalid second-factor challenge.');
        }
    }

    /** @return array{second_factor_required: bool, challenge: string, challenge_expires_at: string, enrollment_required: bool, totp_secret?: string, provisioning_uri?: string} */
    public function response(): array
    {
        $result = [
            'second_factor_required' => true,
            'challenge' => $this->challenge,
            'challenge_expires_at' => $this->expiresAt->format(\DateTimeInterface::ATOM),
            'enrollment_required' => $this->enrollmentRequired,
        ];
        if ($this->enrollmentRequired && $this->totpSecret !== null && $this->provisioningUri !== null) {
            $result['totp_secret'] = $this->totpSecret;
            $result['provisioning_uri'] = $this->provisioningUri;
        }
        return $result;
    }
}
