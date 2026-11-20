<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/** Immutable Auth module migration compiled by SymSvel Tooling. */
final class Version20200101000500 extends AbstractMigration
{
    public function up(Schema $schema): void
    {
        $table = $schema->createTable('symsvel_auth_access_tokens');
        $table->addColumn('id', 'integer', ['autoincrement' => true]);
        $table->addColumn('context', 'string', ['length' => 8]);
        $table->addColumn('principal_id', 'integer');
        $table->addColumn('family_id', 'string', ['length' => 32]);
        $table->addColumn('token_hash', 'string', ['length' => 64]);
        $table->addColumn('expires_at', 'datetime_immutable', ['precision' => 6]);
        $table->addColumn('created_at', 'datetime_immutable', ['precision' => 6]);
        $table->addColumn('revoked_at', 'datetime_immutable', ['precision' => 6, 'notnull' => false]);
        $table->setPrimaryKey(['id']);
        $table->addUniqueIndex(['token_hash'], 'uniq_symsvel_auth_access_hash');
        $table->addIndex(['context', 'family_id'], 'idx_symsvel_auth_access_family');
        $table->addIndex(['expires_at'], 'idx_symsvel_auth_access_expiry');
    }

    public function down(Schema $schema): void
    {
        $schema->dropTable('symsvel_auth_access_tokens');
    }
}
