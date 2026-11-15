<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/** Durable fixed-window reservations for password reset request throttling. */
final class Version20200101000503 extends AbstractMigration
{
    public function up(Schema $schema): void
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

    public function down(Schema $schema): void
    {
        $schema->dropTable('symsvel_auth_reset_limits');
    }
}
