<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Token;

use Symfony\Component\DependencyInjection\Attribute\AutoconfigureTag;

/**
 * Initial authenticated session issuance, never refresh rotation.
 * Runs inside the token store transaction. Implementations may write only
 * transactional state on the shared DBAL connection, with no external effects.
 */
#[AutoconfigureTag('symsvel.auth.session_issued_listener')]
interface SessionIssuedListener
{
    public function onSessionIssued(TokenSubject $subject, \DateTimeImmutable $at): void;
}
