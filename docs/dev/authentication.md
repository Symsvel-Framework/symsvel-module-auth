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
