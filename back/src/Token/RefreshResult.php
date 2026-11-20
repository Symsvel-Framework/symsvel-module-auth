<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Token;

final readonly class RefreshResult
{
    public function __construct(
        public RefreshDecision $decision,
        public ?TokenPair $pair = null,
    ) {
        if (($decision === RefreshDecision::Rotate) !== ($pair !== null)) {
            throw new \InvalidArgumentException('Inconsistent refresh result.');
        }
    }
}
