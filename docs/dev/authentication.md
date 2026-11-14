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

## Déconnexion par famille de tokens

`TokenLogout` prend un secret refresh opaque, un contexte `bo` ou `app` et un instant UTC. Dans une transaction, il recherche et verrouille le refresh par son empreinte SHA-256, vérifie son contexte et son état de révocation, puis révoque **tous les access et refresh tokens de sa famille**. Un contexte erroné ou un secret malformé n'entraîne aucune révocation. L'opération est idempotente du point de vue de la sécurité : un refresh déjà révoqué renvoie `false`.

La déconnexion n'expose aucun endpoint. Le transport navigateur, les cookies et l'authentification Symfony restent à raccorder après revue des contrats existants. Les tests couvrent le service isolé et la persistance DBAL.

## Tests indépendants et autoload (14/11)

Le double `InMemoryTokenStore` possède son propre fichier PSR-4 `back/tests/Token/InMemoryTokenStore.php`, au lieu d'être déclaré à la fin de `TokenRotationTest.php`. Les tests `TokenLogoutTest` peuvent donc être exécutés seuls, sans dépendre de l'ordre de chargement des classes par PHPUnit. Un scénario supplémentaire vérifie qu'une déconnexion répétée sur un refresh déjà révoqué n'émet aucune nouvelle révocation.

## Émission initiale et cycle de session (14/11)

`TokenIssuer` centralise l'émission initiale d'une nouvelle famille de tokens. Il accepte un `TokenSubject` (contexte `bo` ou `app` et identifiant), utilise `TokenFactory`, puis persiste la paire dans la transaction `TokenStore`. Le secret brut n'est pas persisté. **Précondition impérative :** l'appelant doit avoir déjà authentifié le compte et vérifié qu'il est actif ; ce service n'effectue ni vérification de mot de passe ni recherche Admin/User.

La matrice DBAL couvre désormais le cycle complet `émission → vérification access → rotation → déconnexion` pour App, ainsi que deux sessions BO indépendantes appartenant au même administrateur. La déconnexion d'une famille ne doit pas invalider les autres familles du compte. Les durées restent celles de `TokenPolicy` et l'intégration Symfony Security reste séparée.

Les nouveaux commits nécessitent confirmation CI et crash-tests réels sur PostgreSQL, MySQL, MariaDB et SQLite avant clôture du chantier.

## Révocation de toutes les sessions d'un compte

`TokenSessionRevoker::revokeAll(TokenSubject, DateTimeImmutable)` révoque, dans une transaction, **tous les access et refresh tokens** du compte ciblé. La sélection utilise impérativement le couple `(context, principal_id)` : un Admin BO et un User App portant le même identifiant numérique sont des comptes distincts. Les autres comptes du même contexte ne sont pas affectés.

Cas d'utilisation prévus : désactivation d'un compte, changement/réinitialisation du mot de passe, suspicion de compromission. **Le service ne décide pas qui est autorisé à l'appeler** ; la couche d'authentification et les modules propriétaires du compte doivent imposer les contrôles d'accès et déclencher la révocation. Aucun endpoint public n'est ajouté.

Tests : double mémoire (transaction) et matrice DBAL avec deux sessions BO du même compte, un autre administrateur et un utilisateur App partageant le même ID. Après révocation, les access et refresh du compte ciblé sont inutilisables, tandis que les autres sessions restent valides.

## Intégrité transactionnelle : tests d'échec (14/11)

La matrice DBAL couvre deux scénarios supplémentaires sur chaque moteur configuré :

1. **Échec du second INSERT** : une collision volontaire sur l'empreinte unique du refresh provoque une exception de contrainte. L'access inséré juste avant dans la même transaction doit être annulé, sans toucher au refresh préexistant.
2. **Échec après révocation** : une exception forcée après `revokeSubject` doit restaurer la validité des access et refresh tokens de la session. La révocation de compte est atomique, jamais partielle.

Ces scénarios vérifient les garanties de rollback réelles du stockage DBAL. Ils ne prouvent pas encore la sérialisation de deux rotations concurrentes ; un crash-test à deux connexions reste nécessaire avant validation finale. Les CI des nouveaux commits doivent être confirmées.

## Concurrence SQLite : verrou avant lecture (14/11)

Le verrouillage du refresh SQLite n'utilise pas `SELECT FOR UPDATE`, indisponible sur ce moteur. Après l'ouverture d'une transaction DBAL, `DbalTokenStore::lockRefresh` exécute un `UPDATE ... SET token_hash = token_hash WHERE token_hash = ?` avant le `SELECT`. Cette mise à jour sans changement logique acquiert le verrou d'écriture SQLite **avant** toute lecture du token, empêchant deux transactions de lire simultanément le même refresh encore vierge puis de se concurrencer lors de leur passage en écriture. PostgreSQL, MySQL et MariaDB conservent `SELECT FOR UPDATE`.

`SqliteRefreshLockTest` crée une base SQLite temporaire sur disque et deux connexions DBAL distinctes. La première verrouille le refresh dans une transaction ; la seconde, configurée avec `busy_timeout = 0`, doit échouer sans lire un état exploitable. Après libération du verrou, la seconde doit pouvoir lire le refresh normalement. Le fichier temporaire est supprimé en fin de test et la base de test configurée par l'environnement n'est jamais utilisée pour ce scénario.

Sous charge réelle, une erreur SQLite `database is locked` reste possible : elle doit être traitée comme un échec fermé par la couche HTTP (pas comme une rotation réussie). Le test prouve la contention entre deux connexions, **pas** encore une rotation parallèle orchestrée par deux processus. Cette dernière reste à éprouver localement avec les quatre SGBDR. Ne pas activer un retry automatique de toute la transaction sans étude des effets de bord.
