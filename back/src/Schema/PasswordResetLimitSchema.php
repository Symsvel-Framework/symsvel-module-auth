<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Schema;

use Doctrine\DBAL\Schema\Schema;

final class PasswordResetLimitSchema
{
    public static function apply(Schema $schema): void
    {
        $table = $schema->createTable('symsvel_auth_reset_limits');
        $table->addColumn('context', 'string', ['length' => 8]);
        $table->addColumn('scope', 'string', ['length' => 16]);
        $table->addColumn('key_hash', 'string', ['length' => 64]);
        $table->addColumn('window_start', 'integer');
        $table->addColumn('expires_at', 'datetime_immutable', ['precision' => 6]);
        $table->setPrimaryKey(['context', 'scope', 'key_hash', 'window_start']);
        $table->addIndex(['expires_at'], 'idx_symsvel_auth_limit_expiry');
    }
}
