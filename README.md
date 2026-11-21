# Auth

> [!IMPORTANT]
> **Vous souhaitez utiliser SymSvel ? Rendez-vous sur [SymSvel CLI](https://github.com/Symsvel-Framework/symsvel-cli).** Ce dépôt est un **composant du framework**, pas un point d'installation autonome. Création de projets, installation des modules et mises à jour passent par la CLI. Les éventuelles commandes Composer, npm ou Symfony décrites ci-dessous concernent le travail des mainteneurs, sauf indication explicite contraire.

> [!WARNING]
> **SymSvel est en cours de développement.** Les fonctionnalités et procédures peuvent évoluer ou présenter des anomalies. **Utilisation à vos risques et périls.**

Module SymSvel (manifest schema 1).

Le module Auth ne fournit qu'un composant `back`. Il porte l'authentification des contextes BO et, lorsque l'App est installée, App, sans posséder d'écrans Svelte propres.

Les interfaces de connexion relèvent des composants BO et App correspondants. Les modalités techniques d'intégration à Symfony Security restent à définir après audit des modules existants et validation architecturale.

## Sécurité des connexions BO

Dans la distribution standard, `symsvel-framework/module-two-factor` est installé automatiquement. Après authentification du mot de passe, chaque nouvelle connexion BO exige un challenge TOTP. Si le provider de second facteur manque ou n'émet pas de challenge, Auth échoue sans créer de session. L'App conserve une politique facultative ; Google/OIDC est réservé à l'App et n'est pas fourni par ce module. Voir `docs/dev/authentication.md`.

## Distribution stable v1.0.0 (20/11/2026)

Le manifeste Composer du tag stable déclare exclusivement des contraintes `^1.0` pour ses dépendances SymSvel : `symsvel-framework/module-mails`, `symsvel-framework/module-settings`, `symsvel-framework/module-acls`. Les références `dev-dev` restent réservées à la branche `dev` et à l'installation de maintenance avec `--dev`. Le tag `v1.0.0` n'est à publier **qu'après** le tag stable de chaque dépendance, son indexation dans Satis et la réussite des contrôles CI ; aucune release n'est produite par ce commit.

---

## Participer et soutenir le projet

SymSvel est un projet en cours de développement. Pour contribuer, proposer une amélioration ou échanger avec le mainteneur : **[xavier@xavier-tezza.fr](mailto:xavier@xavier-tezza.fr)**.

SymSvel vous est utile et vous souhaitez me remercier ? **Offrez-moi une bière ! 🍺** (lien PayPal à compléter avant l'ouverture publique).
