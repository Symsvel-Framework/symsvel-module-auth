<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Token;

enum RefreshDecision: string
{
    case Rotate = 'rotate';
    case Reject = 'reject';
    case RevokeFamily = 'revoke_family';
}
