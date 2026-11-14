# Auth : socle des tokens (chantier en cours)

## Périmètre

Auth est un module Back unique, pour deux contextes indépendants : `bo` (obligatoire) et `app` (uniquement si App installée). Il ne contient pas d'écran Svelte. Roles et ACLs restent responsables des permissions. La 2FA est un module séparé et facultatif.

## Héritage XCore

Le socle conserve les tokens opaques aléatoires de 256 bits, les empreintes SHA-256 et les durées historiques de 15 minutes (access) et 30 jours (refresh). Les durées restent provisoires jusqu'à validation de la politique de sécurité.

`TokenFactory` génère des paires sans accès BDD, distingue les contextes et permet de réutiliser un identifiant de famille lors d'une rotation. **Elle ne réalise pas la rotation ni sa sécurité transactionnelle.**

## Invariants à imposer à l'intégration

- Stocker uniquement les empreintes, jamais les secrets bruts ; ne jamais les journaliser.
- Associer chaque token à un contexte BO ou App et vérifier ce contexte à chaque accès et refresh.
- Consommer le refresh token de façon atomique dans une transaction, y compris en concurrence ; rejeter les rejeux et révoquer la famille.
- Révoquer les access tokens de la famille lors d'une rotation, conformément à la politique XCore, et lors de la déconnexion.
- Refuser les comptes désactivés ; ne jamais exposer de routes App dans une installation BO seule.
- Définir les règles de stockage et de transport côté navigateur, CSRF/CORS, cookies, déconnexion, limitation des tentatives et nettoyage des tokens expirés avant ouverture des endpoints.
- Aucun contournement de 2FA si une politique future l'impose.

## État de validation

Tests unitaires ajoutés pour la génération et les invariants de base. Pas de validation CI ni de crash-test local à ce stade. Aucun endpoint ni firewall activé. La conception des repositories, de l'intégration Symfony Security et des migrations Doctrine Schema reste à auditer/valider avant implémentation.

## Politique de renouvellement (socle ajouté)

`RefreshTokenGuard` évalue un instantané de refresh token pour un contexte explicite. Il produit `Rotate` pour un token valide, `Reject` pour un token expiré, révoqué ou d'un autre contexte, et `RevokeFamily` si le token a déjà été consommé. Cette distinction empêche de révoquer une famille BO en présentant simplement son token dans le contexte App.

**Attention :** cette décision est pure et ne consomme aucun token. Le futur service de rotation doit verrouiller la ligne du refresh token et effectuer la consommation, la révocation des anciens access tokens et la création du nouveau couple dans **une seule transaction**. Les courses entre requêtes et les défaillances de transaction doivent être couvertes par des tests d'intégration PostgreSQL, MySQL, MariaDB et SQLite avant tout endpoint public.

## Orchestration transactionnelle (nouvelle passe)

`TokenRotation` orchestre le renouvellement via le contrat `TokenStore`. Les tests couvrent le succès, le rejeu, le mauvais contexte, une consommation concurrente perdue et le rejet précoce d'un secret malformé.

Le contrat impose : verrouiller le refresh, vérifier le contexte, effectuer une transition conditionnelle `fresh -> used`, révoquer les anciens access tokens de la famille, persister la nouvelle paire et valider le tout dans une transaction. Un échec de consommation entraîne la révocation de la famille.

**Limite actuelle :** `TokenStore` est une interface ; aucun adaptateur Doctrine/DBAL n'est encore branché. Les tests utilisent un faux stockage, sans garantie réelle d'atomicité ou de rollback. La garantie inter-processus dépendra de l'adaptateur, des contraintes uniques et de tests de concurrence multi-SGBD. Ne pas exposer ce service via un endpoint avant cette validation. L'état actif du compte devra être revérifié lors du renouvellement par l'intégration à l'identité, avant émission des tokens.

## Adaptateur DBAL et tables (passe du 14/11)

L'adaptateur `DbalTokenStore` implémente le contrat de stockage sur Doctrine DBAL 4. Deux tables dédiées, `symsvel_auth_access_tokens` et `symsvel_auth_refresh_tokens`, sont décrites par `AuthTokenSchema::apply(Schema)` avec index d'empreinte unique, index famille/contexte et index d'expiration. Le manifeste annonce les deux tables.

La rotation utilise `SELECT ... FOR UPDATE` sur PostgreSQL/MySQL/MariaDB ; SQLite utilise désormais les transactions gérées par DBAL et une consommation conditionnelle. La sérialisation inter-processus reste à éprouver sous contention réelle ; les erreurs SQLITE_BUSY doivent être traitées explicitement avant exposition. Le test d'intégration SQLite vérifie une rotation suivie d'un rejeu et de la révocation de famille.

**À vérifier impérativement :** le point d'entrée exact du compilateur Schema SymSvel, la compatibilité DBAL 4 des migrations, la gestion des transactions imbriquées, le comportement réel des verrous et les tests concurrents sur quatre SGBD. La définition Schema n'est pas encore branchée sur le mécanisme de compilation des migrations. Aucun endpoint n'est activé. Le contrôle d'état du principal et la gestion d'éventuelles politiques 2FA restent à intégrer avant exposition.

## Matrice de tests DBAL (14/11, passe suivante)

`DbalTokenStoreMatrixTest` exécute les mêmes scénarios sur SQLite en mémoire par défaut et, si `SYMSVEL_AUTH_TEST_DATABASE_URL` est défini, sur une base réelle PostgreSQL, MySQL ou MariaDB : rotation et rejeu, isolation BO/App, rollback des deux tables, indépendance des familles.

**Sécurité du banc de tests :** utiliser exclusivement une base vide dédiée. Le test refuse de démarrer si les tables Auth existent déjà et supprime les tables créées à la fin de chaque scénario. Ne jamais pointer cette variable sur une base de développement partagée ou de production.

Exemples (avec identifiants fictifs, à remplacer localement) :

```sh
SYMSVEL_AUTH_TEST_DATABASE_URL='postgresql://user:password@localhost:5432/auth_test' composer test
SYMSVEL_AUTH_TEST_DATABASE_URL='mysql://user:password@localhost:3306/auth_test' composer test
```

L'interprétation des timestamps persistés a été explicitement fixée à UTC pour éviter la dépendance au fuseau horaire du serveur PHP.

Cette matrice n'est **pas** un crash-test de concurrence entre deux connexions ; il reste à mettre en place et à valider sur les quatre moteurs. La migration de création de tables doit encore être intégrée au format exact du compilateur SymSvel. Les endpoints restent désactivés.

## Validation des access tokens

`AccessTokenVerifier` vérifie le format du secret opaque, l'empreinte SHA-256, le contexte BO/App, la date d'expiration et l'absence de révocation. `DbalTokenStore` implémente `AccessTokenLookup` via la table des access tokens. Des tests unitaires et un scénario DBAL contrôlent qu'une rotation invalide l'ancien access token et rend utilisable le nouveau.

Le résultat est un `TokenSubject` (contexte et identifiant), **pas une session Symfony authentifiée**. L'intégration Security devra résoudre l'Admin ou l'User actif, refuser les comptes désactivés et appliquer ACL/roles. Aucun endpoint n'est exposé.

## Audit des tests et des transactions (14/11)

Le fichier `back/phpunit.xml.dist` pointait sur des dossiers `tests/Unit`, `tests/Integration` et `tests/Functional` alors que les tests Auth se trouvent dans `back/tests/Token`. La suite pointe désormais sur le répertoire réel, pour que `composer test` les exécute effectivement. Une CI verte antérieure ne prouvait donc pas nécessairement l'exécution de ces tests.

La transaction SQLite n'utilise plus des instructions SQL brutes `BEGIN IMMEDIATE/COMMIT/ROLLBACK` qui désynchronisaient l'état transactionnel de Doctrine DBAL. Elle passe par `beginTransaction/commit/rollBack`. Cette correction préserve la gestion DBAL, mais ne garantit **pas** l'absence de courses sous forte contention SQLite : une stratégie explicite de verrouillage/retry et des crash-tests à deux connexions restent requis.

La matrice vérifie également qu'un refresh inconnu n'entraîne aucune révocation. Aucun endpoint n'est ouvert.

## Compatibilité DBAL 4 (correctif CI)

La détection de SQLite utilise `instanceof Doctrine\\DBAL\\Platforms\\SQLitePlatform` au lieu de `AbstractPlatform::getName()`, supprimé de DBAL 4. Le code reste indépendant des chaînes de noms de plateformes. Cette correction est à revalider en CI ; le diagnostic exact du job rouge n'est pas encore confirmé par ses logs.

## Protection des bases de tests (14/11)

La matrice DBAL garde une trace de la propriété des tables créées par le test. Si le précontrôle détecte une table Auth préexistante et interrompt `setUp()`, `tearDown()` ne la supprime **jamais**. La suppression est réservée aux tables dont le test a achevé la création. Ce garde-fou évite une perte de données sur une base pointée accidentellement vers une installation existante. La matrice reste réservée aux bases de test isolées.

## Durcissement du banc de tests (14/11, passe suivante)

Le nettoyage de la matrice DBAL suit désormais les tables effectivement créées au fil de l'installation du schéma, y compris si une instruction DDL échoue après la création de la première table. Les tables préexistantes ne sont jamais marquées comme appartenant au test. La matrice ajoute les bornes exactes d'expiration : un access ou un refresh arrivant à son expiration est refusé, sans révocation abusive de la famille.

Ces tests ne remplacent pas une simulation de concurrence sur deux connexions indépendantes. La CI du dernier commit doit encore être vérifiée.
