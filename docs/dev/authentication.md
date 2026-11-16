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

Les tests unitaires et la matrice DBAL SQLite sont exécutés en CI (dernier retour utilisateur : vert, 14/11/2026). Les crash-tests locaux multi-SGBD restent à effectuer. Aucun endpoint ni firewall activé. La conception des repositories, de l'intégration Symfony Security et des migrations Doctrine Schema reste à auditer/valider avant implémentation.

## Politique de renouvellement (socle ajouté)

`RefreshTokenGuard` évalue un instantané de refresh token pour un contexte explicite. Il produit `Rotate` pour un token valide, `Reject` pour un token expiré, révoqué ou d'un autre contexte, et `RevokeFamily` si le token a déjà été consommé. Cette distinction empêche de révoquer une famille BO en présentant simplement son token dans le contexte App.

**Attention :** cette décision est pure et ne consomme aucun token. Le futur service de rotation doit verrouiller la ligne du refresh token et effectuer la consommation, la révocation des anciens access tokens et la création du nouveau couple dans **une seule transaction**. Les courses entre requêtes et les défaillances de transaction doivent être couvertes par des tests d'intégration PostgreSQL, MySQL, MariaDB et SQLite avant tout endpoint public.

## Orchestration transactionnelle (nouvelle passe)

`TokenRotation` orchestre le renouvellement via le contrat `TokenStore`. Les tests couvrent le succès, le rejeu, le mauvais contexte, une consommation concurrente perdue et le rejet précoce d'un secret malformé.

Le contrat impose : verrouiller le refresh, vérifier le contexte, effectuer une transition conditionnelle `fresh -> used`, révoquer les anciens access tokens de la famille, persister la nouvelle paire et valider le tout dans une transaction. Un échec de consommation entraîne la révocation de la famille.

**Évolution depuis cette passe :** `TokenStore` dispose désormais de l'adaptateur `DbalTokenStore`, couvert par des tests de rollback et de persistance. La garantie inter-processus dépendra de l'adaptateur, des contraintes uniques et de tests de concurrence multi-SGBD. Ne pas exposer ce service via un endpoint avant cette validation. L'état actif du compte est désormais vérifié par `PrincipalStatus` dans `TokenRotation`, avant consommation et émission des tokens.

## Adaptateur DBAL et tables (passe du 14/11)

L'adaptateur `DbalTokenStore` implémente le contrat de stockage sur Doctrine DBAL 4. Deux tables dédiées, `symsvel_auth_access_tokens` et `symsvel_auth_refresh_tokens`, sont décrites par `AuthTokenSchema::apply(Schema)` avec index d'empreinte unique, index famille/contexte et index d'expiration. Le manifeste annonce les deux tables.

La rotation utilise `SELECT ... FOR UPDATE` sur PostgreSQL/MySQL/MariaDB ; SQLite utilise désormais les transactions gérées par DBAL et une consommation conditionnelle. La sérialisation inter-processus reste à éprouver sous contention réelle ; les erreurs SQLITE_BUSY doivent être traitées explicitement avant exposition. Le test d'intégration SQLite vérifie une rotation suivie d'un rejeu et de la révocation de famille.

**À vérifier impérativement :** le point d'entrée exact du compilateur Schema SymSvel, la compatibilité DBAL 4 des migrations, la gestion des transactions imbriquées, le comportement réel des verrous et les tests concurrents sur quatre SGBD. La définition Schema n'est pas encore branchée sur le mécanisme de compilation des migrations. Aucun endpoint n'est activé. Le contrôle d'état du principal est intégré aux services de login, de vérification access et de rotation, mais les fournisseurs concrets Admins/Users et les éventuelles politiques 2FA restent à intégrer avant exposition.

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

## Enregistrement des services dans Symfony (14/11)

`AuthBundle::loadExtension()` enregistre les services d'émission, rotation, vérification, déconnexion et révocation globale, ainsi que `TokenFactory` et `RefreshTokenGuard`. Le service `DbalTokenStore` reçoit la connexion `doctrine.dbal.default_connection` de l'application hôte. Les interfaces `TokenStore` et `AccessTokenLookup` pointent toutes deux sur **le même service** DBAL : pas de deuxième connexion ni de stockage concurrent dans le module.

L'enregistrement suit la convention `AbstractBundle::loadExtension` déjà utilisée dans les modules Admins et Roles. Le test `AuthBundleServicesTest` vérifie les définitions Symfony, les alias et la référence DBAL. Aucun contrôleur, firewall, provider d'identité, écran Svelte ou endpoint n'est ajouté par ce câblage. La vérification des comptes actifs et l'autorisation restent à raccorder aux modules Admins/Users et à Symfony Security. La CI et les crash-tests du dernier commit restent à confirmer.

## Vérification de l'identité active avant authentification (14/11)

`AuthenticatedTokenResolver` compose `AccessTokenVerifier` et le contrat `Identity\\PrincipalStatus`. Il renvoie un `TokenSubject` uniquement si le secret access est valide **et** si le compte existe toujours et est actif. Un token malformé, expiré, révoqué ou utilisé dans le mauvais contexte n'entraîne aucune interrogation du fournisseur d'identité. Le fournisseur est interrogé à chaque résolution réussie du token, afin de prendre en compte une désactivation du compte sans attendre l'expiration de l'access.

Le contrat `PrincipalStatus::isActive(TokenSubject): bool` est volontairement indépendant des classes Admins et Users. L'application hôte doit fournir une implémentation pour BO et, si App est installée, pour App. **Aucun fournisseur par défaut n'est enregistré** : une intégration sans fournisseur doit échouer lors du câblage Symfony, plutôt que d'autoriser silencieusement un compte. L'interface ne décide pas des rôles, des ACL ni du 2FA. Le test unitaire vérifie la désactivation immédiate et l'absence de consultation du fournisseur sur un token invalide.

Le service est enregistré dans `AuthBundle` mais son intégration à un authenticator Symfony, à l'authentification initiale et aux modules Admins/Users reste à réaliser. Ne pas considérer cette étape comme un firewall opérationnel.

## Connexion initiale par mot de passe (14/11)

`Identity\\PasswordLogin` orchestre le début de session : il demande au contrat `Identity\\PasswordPrincipal::authenticate(context, identifier, password)` une identité **déjà authentifiée et active**, vérifie que son contexte correspond à la demande, puis appelle `TokenIssuer` pour enregistrer atomiquement une paire access/refresh. Un contexte invalide est refusé avant toute consultation du fournisseur ; des identifiants incorrects ou un contexte incohérent n'émettent aucun token. Les secrets du mot de passe et des tokens ne sont pas journalisés.

**Responsabilités :** les modules propriétaires des identités (Admins pour BO, Users pour App) doivent implémenter la recherche, le contrôle du mot de passe Argon2id, la vérification d'activation et les protections contre les tentatives abusives. Auth n'importe aucune classe de ces modules. Le contrat ne remplace ni un authenticator Symfony ni le transport HTTP, et ne rend pas le 2FA obligatoire. Les deux contrats `PasswordPrincipal` et `PrincipalStatus` doivent être fournis par l'intégration de l'application avant activation des parcours correspondants. Aucun endpoint n'est exposé dans cette passe.

Tests : refus d'un contexte inconnu, d'un échec d'authentification et d'un sujet de contexte différent, puis émission unique en transaction pour une identité acceptée. Le conteneur Symfony enregistre désormais `PasswordLogin` et `AuthenticatedTokenResolver`. La CI du nouveau commit reste à confirmer.

## Test de bout en bout des services sur DBAL (14/11)

La matrice `DbalTokenStoreMatrixTest` ajoute un scénario de connexion par mot de passe avec fournisseur d'identité de test, persistance réelle des tokens, vérification de l'access, refus du contexte App, désactivation immédiate du compte, refus d'une nouvelle connexion et révocation de toutes les sessions. Le fournisseur de test n'est **pas** un adaptateur Admins de production ; il simule les contrats `PasswordPrincipal` et `PrincipalStatus` afin de valider l'orchestration sans introduire de dépendance entre modules. Le scénario s'exécute sur SQLite et sur chaque SGBDR explicitement configuré pour la matrice. La CI et les crash-tests doivent encore confirmer cette passe.

## Frontières temporelles des tokens (14/11)

La matrice DBAL vérifie désormais les instants exacts d'expiration : un access est valable juste avant son échéance (précision microseconde), mais rejeté à l'échéance et après ; un refresh présenté à son échéance est rejeté sans consommation ni révocation automatique. Cette couverture protège le comportement `expiresAt <= now` des vérificateurs lors des changements de moteur SQL et de précision temporelle. La CI de cette passe et les crash-tests multi-SGBD restent à confirmer.

## Révocation au renouvellement d'un compte désactivé (14/11)

`TokenRotation` exige désormais `PrincipalStatus` dans son constructeur. Après verrouillage du refresh et validation de la politique de rotation, mais **avant** sa consommation et l'émission de nouveaux secrets, le module vérifie que le compte existe toujours et reste actif. Si ce contrôle échoue, la famille de tokens est révoquée dans la même transaction et la rotation renvoie `Reject` sans nouvelle paire. Les tentatives de replay continuent de déclencher `RevokeFamily` avant ce contrôle ; les contextes incorrects restent refusés sans révoquer une autre famille. Le fournisseur d'identité est obligatoire, sans implémentation permissive de production. Les tests unitaires couvrent le refus, la révocation et l'absence d'émission ; les scénarios DBAL existants utilisent un fournisseur de test explicitement actif. Une CI verte et les crash-tests locaux sont encore nécessaires pour valider cette modification.

### Correctif de compatibilité des tests (14/11)

La nouvelle dépendance obligatoire `PrincipalStatus` de `TokenRotation` a révélé un appel resté à trois arguments dans `DbalTokenStoreTest::testSqliteRotationAndReplay`. Le test injecte désormais `ActivePrincipal`, le double explicitement actif déjà utilisé par les autres tests de rotation. Une revue des instanciations `new TokenRotation(...)` des tests a été effectuée pour éviter un second oubli. Ce correctif n'assouplit pas la vérification de l'identité en production. La CI doit confirmer la correction.

### Vérification DBAL de la désactivation (14/11)

Un test d'intégration supplémentaire dans `DbalTokenStoreMatrixTest` confirme, sur les moteurs configurés, qu'un compte BO désactivé ne peut pas renouveler son refresh : aucun nouveau token n'est émis, le refresh d'origine n'est pas consommé, et les deux lignes access/refresh de sa famille sont révoquées en base. Un autre compte BO reste valide, ce qui vérifie l'isolation des identités. Ce test complète la couverture unitaire ; son exécution CI et les crash-tests restent à valider.

## État consolidé au 14/11/2026

**Validé par les dernières CI rapportées :** tests unitaires et intégration SQLite des services de tokens, login, contrôle du compte actif et révocation des familles. L'adaptateur DBAL existe, les contrats `PasswordPrincipal` et `PrincipalStatus` sont obligatoires. **Non validé :** crash-tests locaux PostgreSQL/MySQL/MariaDB, concurrence réelle entre connexions, branchement des migrations Schema au compilateur, adaptateurs concrets Admins/Users, intégration Symfony Security et politique HTTP/cookies/CSRF/CORS. Les passages précédents de ce document décrivent l'historique de construction, pas toujours l'état actuel ; ce récapitulatif prévaut pour le suivi des chantiers.

## Composition des identités par contexte (14/11/2026)

Le service `ContextIdentityProvider` route les deux contrats `PasswordPrincipal` et `PrincipalStatus` selon le contexte déclaré par `ContextOwnedIdentity::authContext()`. Il collecte les services portant le tag Symfony `symsvel.auth.identity_provider`, refuse les doublons et les contextes invalides, et rejette un contexte sans fournisseur. Le BO seul fonctionne avec Admins ; Users ajoute facultativement le contexte App. Auth ne dépend directement d'aucun module d'identité. Les alias de contrats pointent sur ce routeur. Tests unitaires de composition ajoutés ; CI et intégration complète à confirmer.

## Préparation HTTP et garde de sécurité (14/11/2026)

La composition du conteneur est désormais couverte par une assertion explicite : les contrats `PasswordPrincipal` et `PrincipalStatus` doivent tous deux pointer vers `ContextIdentityProvider`. Le test verrouille aussi l'autowiring du routeur. Cela complète les tests de routage BO seul et BO/App.

**Point de blocage volontaire avant ouverture HTTP :** les invariants documentés plus haut exigent la validation des accès concurrents et des transactions sur les quatre SGBD, ainsi qu'une politique explicite de transport navigateur (cookies ou en-têtes), CSRF/CORS et limitation des tentatives. Les endpoints de connexion/refresh/logout et le firewall ne sont donc pas ouverts par cette passe. Leur implémentation devra suivre la validation de ces points, sans déplacer la logique de sécurité dans Back/Core.

## Matrice DBAL : unicité de consommation (14/11/2026)

`DbalTokenStoreMatrixTest::testConditionalRefreshConsumptionAllowsOnlyOneWinner` vérifie, sur le SGBD sélectionné par `SYMSVEL_AUTH_TEST_DATABASE_URL` (SQLite en mémoire par défaut), qu'un même refresh ne peut réussir deux transitions conditionnelles `fresh -> used` : la première réussit, la seconde renvoie `false` et une seule ligne porte `used_at`. Cette vérification est **séquentielle**, elle ne prétend pas simuler deux transactions simultanées. Le test SQLite à deux connexions vérifie séparément le blocage d'un lecteur concurrent. La concurrence interprocessus réelle sur PostgreSQL, MySQL et MariaDB reste à valider avant ouverture des endpoints HTTP.

## Contentions entre connexions indépendantes (14/11/2026)

`RefreshLockContentionTest` ouvre deux connexions DBAL distinctes sur une même base de test jetable. La première verrouille le refresh dans une transaction ; la seconde doit échouer à acquérir ce même verrou avant la fin de la première transaction. Après rollback, la seconde doit pouvoir accéder à la ligne. Pour empêcher les CI de rester bloquées, le test fixe un délai d'attente court : SQLite `busy_timeout=0`, PostgreSQL `lock_timeout=200ms`, MySQL/MariaDB `innodb_lock_wait_timeout=1`.

Par défaut, ce test utilise un fichier SQLite temporaire. Pour chaque moteur externe, définir `SYMSVEL_AUTH_TEST_DATABASE_URL` vers **une base vide exclusivement réservée aux tests**, puis lancer `composer qa`. Les deux tables Auth sont créées et supprimées par le test. **Ne jamais utiliser une base projet ou de production.**

Cette épreuve démontre une contention de verrou sur deux connexions, pas encore une course interprocessus complète aboutissant à une rotation concurrente ; cette dernière et les crash-tests locaux sur les quatre SGBD restent à valider avant toute exposition HTTP.

### Compatibilité DBAL 4 : détection des plateformes

Le test de contention détecte désormais SQLite, PostgreSQL et les plateformes MySQL/MariaDB via `instanceof` (`SQLitePlatform`, `PostgreSQLPlatform`, `AbstractMySQLPlatform`), et non via `getName()` qui n'existe pas dans DBAL 4. Correction suite à l'échec CI du 14/11/2026 (47 tests, 1 erreur).

### Visibilité interconnexion après consommation

Le test de contention vérifie aussi qu'après la libération du verrou, une consommation validée par la connexion A est visible depuis la connexion B (`usedAt` renseigné), et que B ne peut pas consommer une seconde fois le même refresh. Cela complète le contrôle de verrouillage ; il ne remplace pas une course de rotations simultanées entre processus.

## CI multi-SGBD (14/11/2026)

Le workflow `.github/workflows/qa.yml` conserve le job SQLite et ajoute une matrice de services éphémères PostgreSQL 17, MySQL 8.4 et MariaDB 11.4. Chaque job utilise sa propre base `symsvel_auth`, attend que DBAL puisse se connecter, puis lance les tests d'intégration DBAL et de contention avec `SYMSVEL_AUTH_TEST_DATABASE_URL`. Les identifiants de cette matrice sont réservés aux conteneurs CI jetables et ne doivent jamais être réutilisés sur un serveur accessible. La validation effective reste conditionnée aux résultats des nouveaux jobs et aux crash-tests locaux utilisateur.

### Correction du contrôle de disponibilité CI

Le script PHP inline du job de matrice utilise désormais le namespace DBAL avec des antislashs PHP simples (`\Doctrine\DBAL\DriverManager`) : le shell entre apostrophes ne nécessite pas de doubler les antislashs. Cette correction traite l'erreur de parsing rencontrée avant l'exécution des tests sur les trois moteurs.

### Diagnostic de disponibilité de la matrice (14/11/2026)

Après correction de la syntaxe PHP, les trois jobs de matrice échouaient au contrôle de disponibilité, mais le script masquait systématiquement l'exception DBAL. Le contrôle conserve désormais la dernière erreur de connexion et affiche son message en fin de délai, afin de distinguer un problème de pilote, d'URL, d'authentification ou de disponibilité du conteneur. Cette passe n'affirme pas avoir corrigé la cause sous-jacente ; elle la rend observable pour la prochaine CI.

### DSN DBAL 4 : sélection explicite du pilote

La CI a révélé que `DriverManager::getConnection(['url' => ...])` ne sélectionne pas automatiquement de pilote dans notre version DBAL 4. Le script de disponibilité et les deux suites d'intégration utilisent maintenant `Doctrine\\DBAL\\Tools\\DsnParser` avec une correspondance explicite : `postgresql` → `pdo_pgsql`, `mysql` et `mariadb` → `pdo_mysql`. Les connexions SQLite locales continuent d'utiliser leurs paramètres DBAL natifs. La validation reste soumise à la prochaine CI multi-SGBD.

### Sonde DBAL 4

La méthode `Connection::connect()` étant protégée dans DBAL 4, le contrôle de disponibilité CI exécute désormais `SELECT 1` via `executeQuery()->fetchOne()`. Cette sonde utilise l'API publique et vérifie une connexion réellement exploitable.

### Crash-test de rotations simultanées (14/11/2026)

`RefreshLockContentionTest::testConcurrentRotationsHaveOneWinnerAndRevokeOnReplay` lance deux processus PHP (`pcntl_fork`) avec des connexions DBAL indépendantes. Le premier effectue une rotation et conserve le verrou pendant qu'il signale au second de tenter la même rotation. Après le commit du premier, le second doit détecter le rejeu et révoquer la famille, y compris les deux refresh tokens. Le test utilise un canal local de synchronisation et une base jetable, et saute uniquement lorsque l'extension `pcntl` n'est pas disponible. La validation reste conditionnée à la CI sur les quatre moteurs et aux crash-tests locaux.

### Interblocage de rotation MariaDB (14/11/2026)

Le crash-test à deux processus a mis en évidence `SQLSTATE[40001] / 1213` (deadlock) sur MariaDB 11.4. `TokenRotation` relance uniquement la **transaction complète** lorsqu'une exception DBAL implémente `RetryableException`, avec au maximum deux nouvelles tentatives et une attente bornée (100 puis 200 ms). Le rollback du stockage intervient avant chaque nouvelle tentative. Aucun résultat ni paire de tokens n'est retourné avant le commit ; une nouvelle lecture du refresh doit constater son éventuelle consommation et appliquer la révocation de famille. Les erreurs non réessayables ne sont pas interceptées. Ce comportement doit être validé par la matrice CI, notamment MariaDB, puis par crash-test local.

## Endpoint de connexion BO (14/11/2026)

Le contrôleur `BoLoginController` expose `POST /apibo/auth/login` via la recipe de routes Auth. Il exige un corps JSON avec `email` et `password`, délègue au service `PasswordLogin` existant en contexte `bo`, renvoie 401 pour les identifiants refusés, 400 pour une requête invalide et 415 pour un contenu non JSON. Une connexion acceptée renvoie les tokens opaques access/refresh et leurs expirations, avec `Cache-Control: no-store`. Aucun mot de passe ni secret n'est journalisé par ce contrôleur.

**Non terminé :** la politique CORS/origine, la limitation des tentatives, le transport navigateur des secrets, la vérification Bearer sur les routes protégées, le renouvellement, la déconnexion HTTP et les tests fonctionnels avec Admins doivent être validés avant de considérer la connexion BO utilisable en production. Ne pas stocker les tokens dans localStorage. Le dashboard reste verrouillé jusqu'à cette intégration.

## Vérification de session BO

`GET /apibo/auth/me` exige `Authorization: Bearer <access_token>`. Le contrôleur délègue à `AuthenticatedTokenResolver` : empreinte du token, expiration, contexte `bo` et statut actif de l'administrateur sont contrôlés avant de renvoyer `{ "id": 1, "context": "bo" }` (identifiant illustratif). Les requêtes sans Bearer valide renvoient 401, sans cache. Ce point d'entrée ne remplace **pas** l'intégration du firewall Symfony ni l'application des ACL aux autres endpoints.

La CI doit encore valider ce changement. Ne pas ouvrir le dashboard ni conserver les tokens côté navigateur avant validation de la politique de transport, du renouvellement et de la déconnexion.

## Déconnexion BO avec liaison de famille (14/11)

`POST /apibo/auth/logout` accepte un Bearer access et un JSON `{ "refresh_token": "…" }`. `BoSessionLogout` vérifie en base que les deux empreintes correspondent au **même contexte BO, même administrateur et même identifiant de famille**, avec des tokens actifs et non expirés, avant de révoquer la famille. Un refresh provenant d'une autre session ne suffit donc pas à déconnecter celle du Bearer. La réponse de succès est 204 sans cache ; un couple invalide renvoie 401.

**Validation encore nécessaire :** tests DBAL multi-SGBD, concurrence et intégration HTTP. Le transport navigateur et la protection globale des routes BO restent à raccorder. Ne pas considérer cette route comme validée pour la production tant que les crash-tests ne sont pas terminés.

## Régression SQLite de déconnexion liée

`BoSessionLogoutTest` crée trois familles indépendantes, deux BO pour le même administrateur et une App. Il vérifie qu'un couple access/refresh provenant de deux familles distinctes est refusé, qu'un couple App est refusé par la route BO, que la révocation est idempotente et que la déconnexion d'une famille ne révoque pas les autres. Ce test n'établit pas encore la sûreté sous concurrence PostgreSQL/MySQL/MariaDB ni le transport navigateur.

## Renouvellement BO

`POST /apibo/auth/refresh` reçoit un JSON `{"refresh_token":"..."}`, sans access token requis. Il appelle `TokenRotation` dans le contexte strict `bo`, avec verrouillage/consommation du refresh et rotation de la famille. En succès (HTTP 200), il retourne les nouveaux `access_token`, `refresh_token`, `expires_at`, `refresh_expires_at` et `token_type: Bearer`. En cas de refresh invalide, expiré, rejoué ou d'un autre contexte, il retourne HTTP 401 ; entrée invalide HTTP 400 ; média incorrect HTTP 415. Réponses non cachables. Le refresh précédent ne doit jamais être réutilisé.

Le contrôleur est couvert pour la validation d'entrée ; la rotation DBAL est couverte séparément. Le branchement Svelte, le transport HttpOnly/CSRF/CORS et les crash-tests inter-SGBD restent à valider avant usage en production.

## Injection des fournisseurs d'identité (CT installation)

`AuthBundle` configure explicitement l'argument `$providers` de `ContextIdentityProvider` avec un `TaggedIteratorArgument('symsvel.auth.identity_provider')`. L'attribut sur le constructeur ne suffit pas dans ce chemin d'enregistrement manuel des services : l'autowiring du conteneur échouait pendant l'installation initiale sur l'argument `iterable`. Le contrat reste identique : les modules d'identité fournissent des services taggés, avec contexte `bo` ou `app`, et Auth n'impose pas Users. Le test `AuthBundleServicesTest` verrouille cet argument. Validation finale : CI puis reprise du crash-test d'installation vierge.

## Migration initiale des tokens (15/11/2026)

Les migrations initiales sont réparties en deux fichiers autonomes : `Migration/Version20200101000500.php` crée/supprime `symsvel_auth_access_tokens`, et `Migration/Version20200101000501.php` crée/supprime `symsvel_auth_refresh_tokens`. Chaque `up(Schema)` décrit explicitement une seule table avec les opérations Doctrine Schema, sans boucle ni classe auxiliaire, et chaque `down(Schema)` supprime uniquement cette table. Le Tooling compile cette source avec les migrations des autres modules et traduit le diff Schema selon le SGBD choisi au Setup. La migration est nécessaire avant tout appel à `/apibo/auth/login`.

Validation restante : CI et crash-tests locaux PostgreSQL, MySQL, MariaDB et SQLite. Les mentions historiques ci-dessus indiquant que la migration est absente ou non branchée sont désormais obsolètes.

### Conformité aux migrations Schema (15/11/2026)

Les migrations sources `Version20200101000500.php` et `Version20200101000501.php` définissent chacune directement les colonnes, clés et index de leur table dans `up(Schema)`, comme les autres modules natifs et comme les sorties de `module:migrate`. Le compilateur extrait uniquement les corps de `up()` et `down()` : aucune classe auxiliaire du module ne doit être appelée depuis une migration compilée. `AuthTokenSchema` reste utilisé uniquement pour préparer les bases temporaires des tests de stockage des tokens, et n'est plus une dépendance de la migration. Correction motivée par l'échec du CT MySQL `DoctrineMigrations\\AuthTokenSchema not found`. CI et nouveau CT à valider.

## Modèles de mails de récupération (intégration en cours)

Auth dépend désormais du module Mails (et indirectement de Settings). `AuthMailTemplateProvider` déclare deux modèles distincts : `auth.bo.password_reset` et `auth.app.password_reset`. Ils partagent pour l'instant des contenus transactionnels natifs, localisés en français et en anglais dans `back/templates/mail/password-reset/{fr,en}/`, avec sujet, HTML et texte. Le provider utilise les chemins Twig `@Auth/mail/password-reset/...` ; leur résolution doit être confirmée dans un projet Symfony installé. Chaque modèle exige uniquement `resetUrl`.

Le registre Mails assure la sélection de langue, la validation des variables et le rendu. **Aucun endpoint de demande ou consommation de reset, token de récupération, ni envoi n'est encore branché** : ces modèles ne doivent pas être interprétés comme un parcours de récupération opérationnel. Le futur flux doit garantir des tokens à usage unique, expiration, séparation stricte BO/App, non-divulgation de l'existence d'un compte et révocation des sessions après changement du mot de passe. Tests unitaires de déclaration ajoutés ; CI et CT d'intégration à confirmer.

## Authentification Composer des dépendances privées en CI

Depuis l'ajout de la dépendance `symsvel-framework/module-mails:dev-dev`, le dépôt Auth doit pouvoir récupérer Mails sur GitHub privé. Les deux jobs du workflow `.github/workflows/qa.yml` (tests et matrice PostgreSQL/MySQL/MariaDB) reprennent le mécanisme déjà utilisé dans la CI Mails : lecture du secret `SYMSVEL_READ_TOKEN`, génération temporaire de `COMPOSER_AUTH` avec `github-oauth.github.com`, puis `composer install --prefer-dist`. Aucun jeton n'est versionné ni inscrit dans `composer.json`.

Le secret doit être accessible au dépôt Auth et autorisé à lire `Symsvel-Framework/symsvel-module-mails` ainsi que ses dépendances privées éventuelles. Une absence du secret fait échouer explicitement l'étape d'installation. La CI doit confirmer le correctif et les CT restent nécessaires.

### Résolution des dépendances privées transitives

Composer ne reprend pas les entrées `repositories` des paquets dépendants. Auth doit donc déclarer dans son propre `composer.json` les dépôts VCS de `symsvel-framework/module-mails` **et** de `symsvel-framework/module-settings` : Mails exige Settings en `dev-dev`. Le jeton CI donne accès aux dépôts privés, mais ne remplace pas leur déclaration dans le projet racine. La CI doit confirmer cette résolution avant validation.

### Stabilité Composer de Settings

Le dépôt Settings est désormais découvert par Composer, mais sa branche `dev-dev` n'est pas admissible comme simple dépendance transitive avec la stabilité minimale implicite `stable`. Auth déclare donc explicitement `symsvel-framework/module-settings:dev-dev` dans ses dépendances racine, en complément de Mails. Cette autorisation ciblée n'abaisse pas `minimum-stability` pour les autres paquets. Elle sera réévaluée quand une release de Settings contiendra le contrat de définitions requis par Mails. Validation CI encore attendue.

### Test de rendu des messages natifs

Un test d'intégration légère construit le registre Mails avec le provider Auth et le chargeur Twig sur le répertoire de templates Auth. Il vérifie le rendu des deux contextes en français et anglais, l'échappement HTML des liens et leur conservation dans la partie texte. Ce test ne remplace pas la vérification du namespace Twig `@Auth` dans le conteneur Symfony réel, ni un essai SMTP via Mailpit. CI à confirmer.

### Namespace Twig Auth dans Symfony

`AuthBundle::prependExtension()` déclare explicitement le dossier `back/templates` auprès de Twig sous le namespace `Auth`. Les chemins des modèles `@Auth/mail/password-reset/{fr,en}/...` ne dépendent donc pas d'une découverte implicite des templates du bundle. Cette déclaration reste dans le module Auth ; aucune configuration Twig globale du squelette Back n'est nécessaire. Le test de rendu autonome est vert ; la compilation du conteneur Symfony et le rendu dans une installation complète doivent encore être validés par CI d'intégration ou crash-test local.

### Primitive de jeton de récupération

`PasswordResetToken` génère un secret opaque de 256 bits, encodé en base64url (43 caractères), son empreinte SHA-256 et une échéance (30 minutes par défaut, paramétrable). La primitive refuse les contextes autres que `bo` et `app`, les durées non positives et les secrets malformés. Elle est distincte de `TokenFactory` et des familles de sessions. **Elle ne stocke rien et n'assure pas à elle seule l'usage unique** : il reste à concevoir le dépôt DBAL avec consommation atomique, l'association au compte, la révocation et les contrôles anti-abus avant toute exposition HTTP. Tests unitaires ajoutés, CI à confirmer.

### Persistance des jetons de récupération

La migration Schema `Version20200101000502` ajoute `symsvel_auth_password_reset_tokens` (contexte, identifiant de compte, empreinte SHA-256 unique, dates de création/expiration/consommation). La table est déclarée dans `module.json`, et `PasswordResetSchema` permet les tests SQLite sans SQL DDL propre à un moteur. `DbalPasswordResetStore` utilise la connexion DBAL du projet et une mise à jour conditionnelle atomique `used_at IS NULL AND expires_at > now`, avec filtrage du contexte ; une seule consommation concurrente peut réussir. **Le consommateur final doit englober consommation, modification du mot de passe et révocation des sessions dans une même transaction**. L'API HTTP, la recherche de compte et l'envoi de mail ne sont pas encore raccordés. Tests de concurrence inter-processus et CT multibase à effectuer ; CI en attente.

### Contrat d'identité pour la récupération (en cours)

`PasswordResetIdentity` définit les deux opérations relevant des modules propriétaires de comptes : retrouver un sujet actif à partir d'un identifiant et remplacer son empreinte de mot de passe. `ContextPasswordResetIdentity` répartit les appels entre `bo` et `app`, refuse les doublons et ne résout aucun compte dans un contexte absent. Il ne dépend pas de Users pour une installation BO seule. Un test unitaire couvre cette isolation. **Les implémentations Admins/Users, l'orchestration transactionnelle, les politiques de mot de passe et les endpoints restent à réaliser**. Les changements de mot de passe devront être persistés sur la même connexion et dans la même transaction que la consommation du jeton et la révocation des sessions. CI à confirmer.

### Raccordement des propriétaires de comptes

`AuthBundle` injecte les services marqués `symsvel.auth.password_reset_identity` dans `ContextPasswordResetIdentity`. Le module Admins fournit désormais un adaptateur BO DBAL, sans imposer Users dans les installations BO seules. L'adaptateur App et l'orchestration transactionnelle restent à réaliser. CI à confirmer.

### Finalisation transactionnelle de la récupération (15/11/2026)

`PasswordResetCompletion` utilise la connexion DBAL commune pour englober dans **une seule transaction** la consommation conditionnelle du jeton, le remplacement de l'empreinte Argon2id par le provider propriétaire du contexte et la révocation des tokens d'accès et de rafraîchissement du compte. En cas de compte indisponible, une exception interne déclenche le rollback avant de renvoyer `false` ; les erreurs DBAL inattendues restent propagées. Le mot de passe doit comporter entre 12 et 1024 octets ; cette borne est provisoire et ne remplace pas la politique applicative complète. Aucun mail ni effet HTTP n'est exécuté dans la transaction. Les tests SQLite vérifient le succès, la révocation, le rejeu, l'isolation des contextes et le rollback sur refus du provider. **Attention :** le double accès transactionnel dans `DbalPasswordResetStore::consume()` utilise des transactions imbriquées DBAL ; la concurrence réelle et les quatre SGBD restent à valider. Le déclenchement de la demande, l'anti-énumération, le rate limiting et les endpoints ne sont pas encore implémentés. CI de cette passe à confirmer.

### Correction syntaxique de l'orchestrateur

Correction de la parenthèse fermante du contrôle `in_array()` dans `PasswordResetCompletion::complete()` et de l'indentation du callback transactionnel. La CI précédente échouait avant exécution des deux tests de complétion (`ParseError`, ligne 28). Aucun changement fonctionnel attendu ; nouvelle CI à confirmer.

### Renforcement du test de persistance (15/11/2026)

Le test `PasswordResetCompletionTest` utilise désormais une table SQLite `test_reset_accounts` et un provider DBAL plutôt qu'une propriété PHP simulant le stockage. Il vérifie la persistance réelle du hash Argon2id, le marquage du jeton et la révocation des deux catégories de sessions. Le scénario d'échec compare l'empreinte avant/après rollback, puis réessaie le même jeton. Ce test ne remplace pas les crash-tests multibase et de concurrence ; CI de cette passe à confirmer.

### Matrice multibase de récupération (15/11/2026)

`PasswordResetMatrixTest` reprend `SYMSVEL_AUTH_TEST_DATABASE_URL` et la matrice CI existante : SQLite en mémoire pour la suite standard, PostgreSQL 17, MySQL 8.4 et MariaDB 11.4 dans le job `database-matrix`. Il crée des tables de test dédiées et vérifie sur la base réelle le rollback d'un refus de modification, la persistance Argon2id, l'isolation BO/App, la consommation unique et la révocation des sessions access/refresh. Il exige une base de test vide et supprime ses tables en fin d'exécution. **Cette matrice ne simule pas deux transactions simultanées** : les crash-tests de contention et d'installation réelle restent distincts. CI de cette passe à confirmer.

### Préparation à la contention du jeton de récupération (15/11/2026)

`DbalPasswordResetStore::consume()` exécute désormais son `UPDATE` conditionnel avant de lire l'identifiant du compte. L'écriture obtient le verrou avant toute lecture dans la transaction, notamment pour éviter une conversion de transaction de lecture en écriture sous SQLite. L'identifiant n'est consulté qu'après une modification unique réussie. La transaction externe de `PasswordResetCompletion` conserve le rollback global. **La concurrence réelle entre deux connexions reste à valider par un test de contention dédié** ; CI de cette correction à confirmer.

### Test de contention du jeton de récupération (15/11/2026)

`PasswordResetLockContentionTest` utilise deux connexions DBAL distinctes, la même URL de base de test dédiée que la matrice et un SQLite fichier temporaire par défaut. La connexion A consomme le jeton dans une transaction non validée ; B doit échouer sous un délai de verrou borné (SQLite `busy_timeout=0`, PostgreSQL `lock_timeout=200ms`, MySQL/MariaDB `innodb_lock_wait_timeout=1`). Après le commit de A, B doit constater un jeton déjà consommé et la base doit contenir exactement une consommation. Ce test vérifie la contention au niveau du stockage ; il ne remplace pas un crash-test HTTP de deux réinitialisations complètes. CI de cette passe à confirmer.

### Revue des routes de récupération (15/11/2026)

La revue du module confirme les conventions `/apibo/auth/*` pour le BO, les providers de récupération par contexte et les templates Mails natifs `auth.bo.password_reset` / `auth.app.password_reset`. Les endpoints de demande et de finalisation de récupération ne sont pas encore exposés : leur contrat et l'envoi doivent être raccordés aux services Mails existants avant ajout. Correction associée : `ContextPasswordResetIdentity` traite désormais un contexte non enregistré par `null`/`false` sans accès à une clé de tableau absente ; le test existant couvre le cas App absent. CI à confirmer.

### Endpoint de finalisation BO (15/11/2026)

`POST /apibo/auth/password-reset/complete` accepte un corps JSON `{ "token": "...", "password": "..." }`, avec secret de récupération de 43 caractères base64url et mot de passe entre 12 et 1024 octets. Le contrôleur délègue à `PasswordResetCompletion` et renvoie `status=completed` en cas de succès, `invalid_reset_token` pour un jeton invalide/expiré, `invalid_request` pour une entrée malformée et `unsupported_media_type` si JSON absent. Les réponses désactivent le cache. Tests unitaires du contrôleur ajoutés ; CI à confirmer.

**Périmètre volontaire :** aucune route App n'est encore déclarée pour ne pas exposer de route App dans une installation BO seule. Le déclenchement de récupération et l'envoi via `RegisteredMailRenderer` et `MailSender` restent à raccorder, avec configuration de l'expéditeur, URL publique de retour et limitation des demandes. Ne pas considérer le parcours utilisable de bout en bout à ce stade.

### Revue du déclenchement de récupération et du transport (15/11/2026)

Le module Mails expose `RegisteredMailRenderer::render()` et `MailSender::send()`. Le second exige explicitement l'adresse et le nom de l'expéditeur ; `MailsSettingDefinitionProvider` déclare `mails.sender_email` et `mails.sender_name`, mais leur lecture effective n'est pas encore raccordée. Le transport utilise `MAILER_DSN`. Aucun endpoint public de demande de récupération n'est donc ajouté avant raccordement de cette configuration, construction sûre de l'URL de retour et limitation des tentatives. Un test HTTP supplémentaire vérifie le succès de la finalisation BO, le hash du nouveau mot de passe et le rejet d'un second appel avec le même jeton. CI à confirmer.

## Adresse de récupération vérifiée : contrat des propriétaires (15/11/2026)

`PasswordResetIdentity::recoveryEmail(TokenSubject): ?string` est désormais le seul contrat pour obtenir la boîte de récupération depuis le propriétaire de l'identité (`Admins` pour `bo`, `Users` pour `app`). Le propriétaire doit vérifier que le compte existe, est actif et que cette boîte est autorisée et vérifiée avant de la renvoyer. Une adresse fournie dans la requête HTTP ne doit **jamais** être utilisée directement comme destinataire.

`ContextPasswordResetIdentity::recoveryEmail()` route la demande exclusivement vers le fournisseur du contexte demandé et refuse les adresses absentes ou syntaxiquement invalides. Les tests couvrent l'isolation BO/App, les comptes non éligibles, les adresses invalides et les fournisseurs dupliqués. Les doubles `PasswordResetIdentity` existants ont été mis à jour.

**Limites :** le contrôle de syntaxe n'est pas une vérification de propriété de l'adresse. Les adaptateurs réels Admins/Users ne sont pas encore raccordés. Il n'y a toujours pas d'endpoint public de demande de récupération, ni d'envoi ni d'anti-abus. La route de finalisation BO existante n'est pas une preuve d'un parcours utilisable. Les CI et crash-tests locaux de cette passe restent à confirmer.

## Orchestration interne de l'envoi de récupération (15/11/2026)

`PasswordResetDispatch` est désormais enregistré par `AuthBundle`. Il réutilise exclusivement `ContextPasswordResetIdentity`, `DbalPasswordResetStore`, `RegisteredMailRenderer` et `ConfiguredMailSender`. Pour le contexte `bo` ou `app`, il recherche le sujet auprès de son propriétaire, récupère une adresse de récupération vérifiée, génère un jeton opaque de 256 bits et le persiste (empreinte SHA-256 uniquement) avant de rendre et d'envoyer le modèle `auth.<contexte>.password_reset`. La langue transmise au renderer utilise son fallback existant. Si aucun sujet ou destinataire éligible n'est trouvé, le service renvoie `false` sans persister ni envoyer.

L'appelant doit fournir une URL de page de récupération issue de la configuration serveur de l'installation ; le service refuse les URL non HTTPS, sans hôte, avec utilisateur/mot de passe, paramètres de requête ou fragment. Le jeton est ajouté comme paramètre `token`. **Ne jamais alimenter cette URL depuis le corps HTTP, l'en-tête Host, Origin ou Referer.** L'absence de configuration fiable des URL BO et App interdit encore d'ouvrir l'API de demande.

**Garanties et limites :** ce service interne ne masque pas la présence d'un compte (son retour `bool` n'est donc pas un contrat HTTP). Un futur contrôleur doit toujours renvoyer une réponse publique indistinguable, appliquer une limitation persistante par compte/IP et empêcher les abus avant d'appeler ce service. Une erreur de transport reste une exception ; un jeton enregistré mais non envoyé expire normalement. Ne jamais journaliser le jeton ni l'URL complète. L'envoi n'est pas réalisé dans une transaction SQL longue. L'interface de récupération n'expose toujours aucune route App dans les installations BO seules.

Le banc `PasswordResetDispatchTest` couvre le rendu réel, un mailer simulé via son interface Symfony, le vrai `ConfiguredMailSender` avec Settings + Doctrine ORM et SQLite en mémoire, la persistance du hash, le refus des comptes inconnus et la validation de l'URL. **Tests CI, crash-tests locaux multi-SGBD, intégration Admins/Users, configuration des URL et anti-abus encore à valider.**

## Limitation persistante des demandes de récupération (15/11/2026)

`PasswordResetLimiter` fournit une primitive interne **fail-closed**, indépendante de tout contrôleur HTTP. La table `symsvel_auth_reset_limits` est déclarée dans le manifeste et la migration Schema native `Version20200101000503` ; la classe `PasswordResetLimitSchema` reproduit cette définition pour les tests. Une clé primaire unique `(context, scope, key_hash, window_start)` empêche deux requêtes concurrentes de réserver le même créneau, sur les moteurs SQL cibles.

`allow(context, identifier, clientIp, now)` réserve atomiquement deux créneaux : **une demande par identifiant et par cinq minutes**, et **une demande par IP et par dix secondes**, pour chaque contexte. Le refus d'un créneau annule l'autre réservation dans la transaction DBAL. Les identifiants et adresses IP ne sont **jamais stockés en clair** : les clés utilisent HMAC-SHA-256 et `kernel.secret` (secret fort et partagé par toutes les instances d'une installation). Le contrôle s'applique même aux identifiants inexistants. Une entrée malformée est refusée, une panne DBAL n'autorise jamais implicitement la demande.

**Intégration encore nécessaire :** le futur adaptateur HTTP devra résoudre l'IP via les proxys de confiance, appeler `allow()` **avant** la recherche du compte, renvoyer la même réponse publique pour les demandes refusées ou inconnues et utiliser une URL de retour issue exclusivement de la configuration serveur. `PasswordResetDispatch` reste interne ; aucun endpoint de demande n'est activé. Les fenêtres fixes peuvent autoriser deux demandes proches d'une frontière ; les seuils sont provisoires, à ajuster après crash-tests et revue. Les créneaux expirés devront être purgés par une opération de maintenance CLI/Tooling, pas par un travail de fond dans le runtime. Le stockage conserve temporairement des empreintes HMAC : la politique de rétention doit être déterminée avant mise en production.

Tests : `PasswordResetLimiterTest` utilise SQLite en mémoire pour la limite par identifiant, la limite par IP, le rollback d'une réservation partielle, l'isolation BO/App et l'absence d'identifiant en clair. **CI et contention réelle multi-SGBDR à confirmer.**

## Application effective du limiteur dans l'envoi (15/11/2026)

`PasswordResetDispatch::dispatch()` exige maintenant `clientIp` en argument. Il vérifie d'abord le contexte et l'URL HTTPS configurée, puis appelle **obligatoirement** `PasswordResetLimiter::allow(context, identifier, clientIp, now)` **avant** toute recherche auprès d'Admins/Users. Une requête refusée ne déclenche donc ni consultation d'identité, ni création de jeton, ni envoi d'e-mail. Les demandes concernant un compte inexistant consomment également leurs créneaux anti-abus, afin de ne pas exposer un chemin gratuit à l'énumération.

Le constructeur exige explicitement le limiteur ; aucun chemin de contournement non limité n'est disponible via le service de dispatch. `AuthBundle` enregistre déjà les deux services et les relie par autowiring. Les tests du dispatch sont étendus pour valider les réservations, le refus des répétitions et l'absence de message supplémentaire. Le test d'enregistrement du bundle contrôle les deux services sans assertion dupliquée.

**Attention :** `clientIp` doit provenir du serveur HTTP après configuration des proxys de confiance. Ce service interne retourne encore un booléen et ne garantit pas une réponse publique uniforme. Les paramètres d'URL, l'identité et le secret du jeton ne doivent jamais être journalisés. Aucun endpoint HTTP de demande n'est ouvert ; la configuration de l'URL BO/App et les adaptateurs réels Admins/Users restent nécessaires. CI et crash-tests réels à confirmer.

## URL fiable des pages de récupération via Settings (15/11/2026)

Auth déclare désormais ses propres paramètres auprès de Settings, par `AuthSettingDefinitionProvider` enregistré avec le tag `symsvel.settings.definition_provider` : `auth.bo_reset_url` et `auth.app_reset_url`. Le type natif est `url`. Les paramètres sont **privés** (`public=false`) et **non bloquants** pendant le Setup (`required=false`, `blocking=false`). La définition App n'active aucune route App dans une installation BO seule.

`PasswordResetUrlResolver` lit exclusivement `SettingManager`, refuse l'absence de valeur et exige une URL HTTPS absolue avec hôte, sans identifiants d'accès, query string ni fragment. `PasswordResetDispatch` injecte directement ce résolveur et **n'accepte plus d'URL en argument** : les en-têtes HTTP, le champ `Host` et les paramètres de requête ne peuvent donc pas choisir la destination du lien. Une URL non configurée échoue avant consommation du quota et avant consultation du compte. L'IP reste un argument fourni par le futur adaptateur HTTP à partir des proxys de confiance.

Les tests couvrent les définitions, le câblage Symfony, les URL BO/App valides, les valeurs absentes et invalides, ainsi que le refus de dispatch lorsque l'URL App est absente. Aucune URL n'est fabriquée automatiquement depuis le domaine local du Setup. **Aucun endpoint public supplémentaire n'est ouvert** et aucune URL de réinitialisation App n'est requise si App est absente. La CI de cette passe et les crash-tests locaux restent à confirmer.

## Intégration des propriétaires et état des boîtes vérifiées (15/11/2026)

Les modules Admins et Users possèdent déjà leurs adaptateurs `AdminPasswordResetIdentity` et `UserPasswordResetIdentity`, enregistrés dans leurs bundles respectifs sous `symsvel.auth.password_reset_identity`. Le contrat complémentaire `recoveryEmail()` y est maintenant implémenté. **Les deux retournent actuellement `null`**, car leurs tables portent `email` et `enabled` mais aucun indicateur de vérification de la boîte. La simple présence d'une adresse ne suffit pas à autoriser l'expédition d'un lien sensible. La recherche du compte et la finalisation transactionnelle demeurent disponibles et inchangées.

Il reste à concevoir la vérification persistante des adresses, puis à activer la récupération pour chaque contexte. En attendant, le dispatch refuse l'envoi après le contrôle anti-abus. Les tests des deux modules vérifient ce refus et l'isolation des contextes. CI de ces commits et crash-tests locaux à confirmer. Aucun endpoint de demande public n'est activé.

## Test de contention du limiteur de récupération (15/11/2026)

`PasswordResetLimiterContentionTest` complète les tests séquentiels existants : il utilise **deux connexions Doctrine DBAL indépendantes** vers un fichier SQLite temporaire privé, jamais vers une base de projet ni vers `SYMSVEL_AUTH_TEST_DATABASE_URL`. La première connexion réserve le créneau identifiant/IP dans une transaction non validée ; la seconde tente de réserver le même identifiant avec une autre IP. Une erreur de verrou SQLite (timeout nul) ou un refus explicite doit empêcher tout second accord. Après validation de la première transaction, la répétition est refusée et seules les deux réservations initiales sont présentes.

**Portée :** ce test couvre un cas de contention SQLite réel, pas une exécution parallèle multiprocessus ni les garanties de PostgreSQL, MySQL et MariaDB. Les crash-tests multi-SGBDR restent requis avant ouverture du parcours HTTP. Aucun changement du runtime ou de la politique de vérification des adresses. Les adaptateurs Admins/Users renvoient toujours `null` tant qu'aucune preuve de vérification persistante de la boîte mail n'est disponible. CI de ce test à confirmer.

## Matrice multi-SGBD : contention du limiteur (15/11/2026)

`PasswordResetLimiterContentionTest` réutilise maintenant la matrice Auth via `SYMSVEL_AUTH_TEST_DATABASE_URL`. Sans variable, il teste deux connexions SQLite distinctes sur un fichier temporaire privé. Avec une URL, il utilise **deux connexions vers la même base de test jetable** sous PostgreSQL, MySQL ou MariaDB. La CI `database-matrix` invoque explicitement ce test en plus de la contention des tokens. Elle configure un délai d'attente de verrou court selon la plateforme (`PRAGMA busy_timeout`, `lock_timeout`, `innodb_lock_wait_timeout`).

Le premier client réserve les deux créneaux dans une transaction non validée ; le second tente le même identifiant depuis une IP différente. Seul un **refus** ou une **exception de verrou** est acceptable ; après commit du premier client, toute répétition est refusée. L'assertion finale contrôle qu'aucune réservation supplémentaire n'a été persistée.

**Précaution impérative :** l'exécution avec `SYMSVEL_AUTH_TEST_DATABASE_URL` crée puis supprime `symsvel_auth_reset_limits` ; elle refuse de démarrer si cette table existe déjà. Ne jamais pointer sur une base partagée ou de production. Ce banc vérifie la contention des deux connexions dans un même processus, mais ne remplace pas les crash-tests d'installation et de charge sur projets XT. La CI de cette extension reste à confirmer ; aucun service de runtime, contrôleur public ou contrat de sécurité n'est modifié.

## Double contention du limiteur de récupération (15/11/2026)

Le test de concurrence multi-SGBD `PasswordResetLimiterContentionTest` utilise désormais un `DataProvider` PHPUnit pour vérifier **les deux verrous fonctionnels** : (1) même identifiant de compte depuis deux adresses IP différentes ; (2) deux identifiants distincts depuis la même adresse IP. Dans chacun des cas, une première réservation reste non validée pendant que la seconde connexion tente de réserver le créneau partagé. Cette dernière doit être refusée (conflit d'unicité ou verrou DBAL), puis demeurer refusée après validation de la première transaction. Deux réservations seulement doivent exister à la fin. Le workflow `database-matrix` existant exécute les deux variantes sous PostgreSQL, MySQL et MariaDB ; le job standard les exécute avec SQLite.

Cette passe **ne modifie ni les seuils, ni le runtime, ni les migrations**. Les adaptateurs Admins/Users restent sans envoi jusqu'à une preuve persistante de vérification de l'adresse. La CI du nouveau test est à confirmer ; les crash-tests locaux des quatre moteurs restent requis.

## Jetons dédiés à la confirmation d'adresse e-mail (15/11/2026)

Conformément à la décision de vérification obligatoire des adresses, Auth fournit un socle de jetons de confirmation distinct de la récupération du mot de passe. `EmailVerificationToken` génère 256 bits aléatoires, encodés en base64url (43 caractères), stockés seulement sous empreinte SHA-256 et valables 60 minutes par défaut. Le jeton est lié à un contexte `bo` ou `app`. Les deux usages ont des tables et opérations séparées.

`DbalEmailVerificationStore` partage la connexion DBAL du projet. `save(subject, email, token, now)` contrôle l'adresse, le contexte et conserve seulement l'empreinte SHA-256 de l'e-mail normalisé avec le hash du jeton. `consume(context, raw, now)` effectue une consommation conditionnelle atomique pour un jeton non expiré et non utilisé, puis retourne le sujet et l'empreinte de l'adresse. La consommation doit être englobée dans la transaction de confirmation du module propriétaire pour permettre un rollback si l'adresse actuelle n'est plus celle demandée.

La migration `Migration/Version20261115000504.php` crée `symsvel_auth_email_verification_tokens` par Doctrine Schema. La table figure dans `module.json`, le store est enregistré dans `AuthBundle` et les tests SQLite couvrent stockage, contexte, rejeu, expiration, validation des entrées et rollback. Le test de composition vérifie le partage DBAL.

**Reste à développer :** la finalisation transactionnelle côté Admins/Users avec vérification de l'empreinte de l'adresse actuelle, l'envoi du mail de confirmation, sa page et son URL fiable, l'anti-abus de confirmation, les routes HTTP et la purge via CLI/Tooling. Un changement d'adresse devra invalider son état vérifié. Aucun compte n'est automatiquement vérifié ; la récupération de mot de passe reste interdite pour les adresses non confirmées. CI et crash-tests multi-SGBD de cette passe à confirmer.

## Confirmation transactionnelle des adresses e-mail (15/11/2026)

`EmailVerificationCompletion` consomme un jeton à usage unique via `DbalEmailVerificationStore` et appelle l'adaptateur du compte propriétaire au sein d'une **même transaction DBAL**. `ContextEmailVerificationIdentity` route exclusivement selon le contexte `bo` ou `app` et refuse les fournisseurs dupliqués ainsi que les empreintes invalides. Une confirmation impossible (compte supprimé/désactivé, adresse modifiée, compte déjà vérifié) déclenche un rollback : le jeton n'est pas perdu, puis expire naturellement. Les erreurs DBAL ne sont pas converties en succès.

`AuthBundle` enregistre le routeur par tag `symsvel.auth.email_verification_identity` et le service de finalisation avec la connexion Doctrine partagée. Les modules Admins et Users implémentent le contrat `EmailVerificationIdentity` sans dépendance d'Auth envers leurs tables.

Tests : `EmailVerificationCompletionTest` vérifie succès, mauvais contexte, rejeu, rollback pour changement d'adresse et refus d'un compte désactivé. `AuthBundleServicesTest` vérifie les définitions de services. Les adaptateurs réels sont testés dans les dépôts propriétaires.

**Périmètre restant :** génération et expédition du mail, construction de l'URL depuis Settings, anti-abus, endpoints et écrans. Aucun endpoint public nouveau n'est activé ; les comptes non vérifiés restent inéligibles à la récupération de mot de passe. CI de cette passe et crash-tests locaux à confirmer.

## Préparation de l'envoi des confirmations e-mail (15/11/2026)

Auth déclare désormais deux paramètres URL supplémentaires dans Settings : `auth.bo_verify_email_url` et `auth.app_verify_email_url`. Ils sont privés, facultatifs pendant le Setup et utilisent le type natif `url`. Le résolveur `EmailVerificationUrlResolver` est enregistré dans `AuthBundle` et accepte uniquement une URL HTTPS serveur avec hôte, sans utilisateur/mot de passe, query string ni fragment. Une URL absente ou dangereuse entraîne un refus ; aucune origine n'est déduite du navigateur ou d'un header HTTP.

`AuthMailTemplateProvider` déclare désormais les quatre modèles transactionnels : récupération de mot de passe et confirmation d'adresse, chacun en contexte BO ou App, avec variantes FR et EN. Les modèles de confirmation utilisent la variable `verificationUrl` et possèdent chacun un sujet, un contenu texte et un contenu HTML via Twig. Les fichiers sont référencés par le registre Mails existant, sans ajout d'un second moteur de rendu.

Les tests des définitions Settings, du résolveur, du registre de modèles et du câblage Symfony ont été actualisés. Les valeurs ne sont pas publiques et n'imposent rien à une installation BO sans App.

**Limite volontaire de cette passe :** aucun service d'expédition n'est encore exposé. Il devra demander l'adresse courante directement au module propriétaire, appliquer une limitation de confirmation indépendante du reset et envoyer seulement à cette adresse. Aucun endpoint HTTP n'a été ajouté. La CI des commits et les crash-tests locaux restent à confirmer.

## Envoi interne des confirmations et limitation distincte (15/11/2026)

`EmailVerificationDispatch` est enregistré dans `AuthBundle`. Il récupère la page de confirmation depuis `EmailVerificationUrlResolver` (Settings privé), applique **avant toute recherche de compte** la limitation dédiée `PasswordResetLimiter::allowVerification()`, puis retrouve le compte via le routeur de contexte existant et demande à `ContextEmailVerificationIdentity::pendingEmail()` l'adresse actuellement détenue par le module propriétaire. L'adresse du destinataire n'est jamais reprise d'un champ HTTP.

Les limites de confirmation utilisent les mêmes garanties de transactions DBAL et HMAC-SHA256, mais des scopes distincts (`verify_id`, `verify_ip`) dans `symsvel_auth_reset_limits`. Les seuils provisoires sont identiques au reset : cinq minutes par identifiant et dix secondes par IP. Ils sont **indépendants** des réservations `identifier` et `ip` du reset, sans nouvelle table ni migration. Une adresse déjà vérifiée ou un compte désactivé ne peut plus obtenir de nouveau mail de confirmation. Le token de confirmation dédié (256 bits) est persisté sous empreinte, puis le message `auth.<context>.email_verification` est rendu via Mails et expédié avec `ConfiguredMailSender`. Les erreurs d'envoi restent propagées ; un token non livré expire normalement.

`EmailVerificationIdentity::pendingVerificationEmail()` est le nouveau contrat propriétaire. Il ne renvoie une adresse valide que pour un compte actif encore non vérifié. Le service de dispatch reste **interne**, retourne un booléen non utilisable comme réponse publique et attend une IP résolue via les proxys de confiance. Les tests couvrent destinataire, modèles FR/EN, URL HTTPS, comptes inconnus, quotas et persistance des hashes. Aucun endpoint BO/App, aucun mécanisme public d'anti-énumération, ni aucune URL issue de la requête n'est introduit. CI et crash-tests à confirmer.

## Point d'entrée HTTP BO pour finaliser la confirmation (15/11/2026)

Le contrôleur `EmailVerificationCompleteController` expose uniquement `POST /apibo/auth/email-verification/complete` avec un corps JSON contenant `token` (secret base64url de 43 caractères). Il appelle `EmailVerificationCompletion::complete('bo', token, now)` et réutilise la transaction DBAL déjà validée entre consommation atomique du jeton et mise à jour de l'adresse par Admins. Il ne récupère ni adresse e-mail ni identifiant de compte depuis la requête. Le succès renvoie `{"status":"completed"}`; un jeton inconnu, expiré, déjà utilisé ou associé à `app` renvoie une erreur générique `invalid_verification_token`. JSON invalide ou absent : 400 ; type non JSON : 415. Toutes les réponses ont `Cache-Control: no-store` et `Pragma: no-cache`.

Le contrôleur est enregistré avec `controller.service_arguments` dans `AuthBundle`. `EmailVerificationCompleteControllerTest` exerce la validation HTTP, le succès, le rejeu et l'isolation BO/App avec le vrai stockage SQLite et un adaptateur propriétaire de test. `AuthBundleServicesTest` vérifie son enregistrement. Aucun point d'entrée App n'est introduit dans une installation BO seule.

**Le parcours n'est pas encore opérationnel de bout en bout :** le déclenchement public des e-mails reste fermé tant que la résolution d'IP (proxys de confiance) et les garanties d'anti-énumération HTTP ne sont pas validées. La page Svelte BO de confirmation n'est pas encore ajoutée. Ce contrôleur est un point d'entrée HTTP sensible : vérifier la CI, la découverte des routes dans le projet assemblé et les crash-tests locaux avant de considérer le chantier terminé.

## Ajustement du test HTTP Cache-Control (15/11/2026)

Symfony HttpFoundation peut compléter `Cache-Control: no-store` par la directive `private`. Le test de confirmation BO vérifie désormais la présence de la directive de sécurité `no-store` via `hasCacheControlDirective('no-store')`, plutôt que de comparer l'en-tête entier à une chaîne exacte. Le comportement de l'endpoint reste inchangé ; il interdit toujours le stockage de la réponse. CI de ce correctif à confirmer.

## Diagnostic des accès GitHub privés dans les CI (15/11/2026)

Le workflow `qa.yml` fournit explicitement le secret GitHub Actions `SYMSVEL_READ_TOKEN` à Composer via `COMPOSER_AUTH` (`github-oauth`). Avant installation, il refuse un secret absent et contrôle en lecture, par l'API GitHub, l'accès aux dépôts privés `symsvel-module-auth`, `symsvel-module-mails` et `symsvel-module-settings`. En cas d'absence, d'expiration ou de permissions insuffisantes, la CI échoue avec un diagnostic explicite **avant** `composer install` plutôt qu'un message générique de Composer. La valeur du jeton n'est jamais affichée. Les runners auto-hébergés ne doivent pas dépendre d'une authentification Composer laissée dans leur cache local.

**Configuration à maintenir :** secret `SYMSVEL_READ_TOKEN` lisible dans chacun des trois dépôts GitHub Actions (ou via une configuration de secrets autorisée), avec droits de lecture sur les dépôts privés requis. Un `GITHUB_TOKEN` standard limité au dépôt du workflow ne suffit pas pour ces dépendances inter-dépôts. Un jeton révoqué ou expiré doit être remplacé dans les secrets GitHub, pas en dur dans `composer.json` ou les logs. CI de ce correctif à confirmer ; aucune modification du runtime.

## Correction du précontrôle de permissions CI (15/11/2026)

Le précontrôle du workflow Auth interroge désormais uniquement les dépôts privés dont Auth dépend directement : `symsvel-module-mails` et `symsvel-module-settings`. Exiger aussi la lecture de `symsvel-module-auth` lui-même ajoutait une permission sans justification technique et pouvait bloquer un jeton à portée restreinte pourtant suffisant pour installer ses dépendances. Admins et Users conservent le contrôle de leurs trois dépendances privées (Auth, Mails et Settings). La disponibilité effective des secrets GitHub et la validité de leurs autorisations ne peuvent pas être déduites du manifeste ; la CI doit les confirmer. Aucun code runtime modifié.

## Décision : validation e-mail et création du mot de passe administrateur (16/11/2026)

L'administrateur initial `ROLE_DEV` est créé via le Setup Wizard **local**, qui est une opération d'initialisation de confiance : son e-mail doit être marqué vérifié à la création, sans message de confirmation. Les futurs administrateurs suivent un **parcours unique d'invitation**, dans lequel la création initiale de leur mot de passe valide simultanément la possession de leur adresse e-mail. Il ne faut pas leur envoyer successivement un lien d'activation et un second lien de vérification. La preuve doit reposer sur un jeton expirant, à usage unique, lié au sujet, à son contexte BO et à son adresse actuelle, avec confirmation et création du mot de passe atomiques.

Les utilisateurs `app` conservent une confirmation d'e-mail obligatoire. Un changement d'adresse impose dans les deux contextes une nouvelle vérification. Auth conserve la responsabilité des secrets et des opérations transactionnelles ; Admins/Users possèdent l'état des comptes, Mails délivre les messages, Setup ne reçoit pas de logique métier Auth.

**Attention** : décision architecturale validée, pas livraison du parcours d'invitation ni du bootstrap adapté. Les endpoints et primitives déjà présents ne doivent pas être présentés comme une preuve de conformité à cette règle avant réalisation des tests et crash-tests.

## Amorce du parcours d'invitation administrateur (16/11/2026)

`Auth/Token/AdminInvitationToken` définit le secret opaque de 256 bits réservé aux invitations BO : empreinte SHA-256, durée de vie par défaut d'une heure, validation stricte du format et rejet d'une durée non positive. `AdminInvitationTokenTest` couvre génération, empreinte, durée et entrées invalides.

**Important** : cette primitive seule n'impose pas une séparation des usages : avant d'activer un endpoint, le dépôt de jetons d'invitation devra disposer d'un stockage ou d'un discriminant de finalité distinct des jetons de réinitialisation et de confirmation, empêcher leur consommation croisée, lier le jeton à l'ID et à l'empreinte de l'adresse actuelle, puis réaliser **dans la même transaction** la consommation, la définition du mot de passe et la confirmation de l'adresse. Cette livraison ne crée encore ni invitation, ni email, ni activation HTTP. Le flux reste non opérationnel avant les tests intégrés et crash-tests.

## Persistance des invitations BO (16/11/2026)

La migration additive `Migration/Version20261116000505.php` définit la table propre à Auth `symsvel_auth_admin_invitations` ; son miroir PHP `AdminInvitationSchema` sert aux tests et reprend les mêmes colonnes et index. Le registre `module.json` inclut cette nouvelle table pour l'installation et la suppression du module.

`DbalAdminInvitationStore` utilise la connexion DBAL partagée et conserve uniquement l'empreinte SHA-256 du jeton et de l'adresse normalisée ; le jeton est lié à l'identifiant de l'administrateur. La consommation repose sur un `UPDATE` conditionnel atomique (non utilisé et non expiré), puis fournit l'identité et l'empreinte de l'adresse. Elle doit être appelée **dans la transaction d'activation** ; les tests SQLite contrôlent usage unique, expiration, invalidité et rollback de consommation. Enregistrement explicite de ce store dans `AuthBundle`.

Il n'existe **toujours pas d'endpoint public ni de flux d'invitation fonctionnel** : à suivre, l'activation atomique de l'administrateur avec contrôle de son adresse actuelle et définition du premier mot de passe, puis l'envoi via Mails et les écrans BO. Les migrations multi-SGBD et crash-tests du projet assemblé ne sont pas encore validés pour cette nouvelle table.

## Activation transactionnelle d'une invitation BO (16/11/2026)

`AdminInvitationCompletion` consomme une invitation depuis `DbalAdminInvitationStore` puis demande à l'unique propriétaire BO d'activer le compte via `AdminInvitationIdentity`, sélectionné au moyen de `AdminInvitationOwners` et du tag `symsvel.auth.admin_invitation_identity`. Le traitement s'effectue dans **une même transaction DBAL** et retourne `false` en cas de jeton invalide, expiré, réutilisé, de mot de passe hors limites ou de refus du compte. Un refus d'activation entraîne un rollback de la consommation. Le mot de passe initial est haché en Argon2id.

Le test `AdminInvitationCompletionTest` vérifie la liaison à l'adresse courante, l'activation atomique, l'impossibilité de réutiliser le jeton, ainsi que le rollback pour un compte désactivé ; `AuthBundleServicesTest` contrôle le câblage Symfony.

**Non livré** : création/invitation d'un nouvel admin, émission du mail, endpoint HTTP et parcours Svelte. Aucun flux public n'est ouvert par cette étape. La CI et les CT multi-SGBD restent à valider.

## Livraison groupée : invitation BO via mail et finalisation HTTP (16/11/2026)

Le paramètre privé `auth.bo_invitation_url` définit l'adresse HTTPS de la page d'activation BO ; `AdminInvitationUrlResolver` refuse HTTP, identifiants intégrés, query strings et fragments. `AdminInvitationDispatch` est un **service interne** : un appelant BO autorisé lui fournit l'identifiant et l'adresse du compte invité après création côté Admins. Il génère le jeton dédié, le conserve sous empreinte et diffuse le message FR/EN `auth.bo.admin_invitation` via Mails. Il n'est pas exposé par un endpoint d'émission anonyme.

`POST /apibo/auth/invitation/complete` reçoit `token` et `password` en JSON, refuse les entrées incorrectes et s'appuie sur `AdminInvitationCompletion` pour consommer le jeton et confirmer le mail en créant le mot de passe dans une même transaction. Les réponses ne sont pas mises en cache et les échecs ne révèlent pas les comptes. Tests du contrôleur, rendu Twig, configuration des templates et câblage Symfony inclus.

**Non terminé** : création et autorisation des administrateurs invités dans Admins (notamment rôle explicite et absence d'habilitation DEV par défaut), envoi sous contrôle du créateur, intégration des écrans Svelte, CI de ce commit et crash-tests multi-SGBD. Aucun parcours complet n'est revendiqué.

## Page publique d'acceptation de l'invitation BO (16/11/2026)

Auth déclare maintenant un scope `bo` dans `module.json` afin que Tooling synchronise la route `/auth/activate` et ses helpers TS. La page Svelte locale traite le jeton éphémère de l'URL, l'efface immédiatement de l'historique, demande une confirmation du nouveau mot de passe et appelle **publiquement et sans credentials** `POST /apibo/auth/invitation/complete`. Le succès ne crée pas automatiquement une session et propose le retour vers `/login`. Le choix de la langue se fonde sur la langue d'interface BO avec textes FR/EN externalisés. Le paramètre `auth.bo_invitation_url` doit cibler exactement cette page HTTPS, sans query string (exemple `https://bo.exemple.test/auth/activate`).

Tests unitaires Svelte/TS du jeton et du mot de passe définis dans `bo/tests/auth.test.ts`. Le scope BO est obligatoire car le BO fait partie de tout projet SymSvel ; App n'est pas rendue obligatoire. Les parcours d'inscription et de confirmation App restent distincts. À vérifier : CI du BO assemblé, URL configurée côté Settings, CORS, délivrance réelle du mail, activation avec migrations multi-SGBD et crash-tests locaux utilisateur.
