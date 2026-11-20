# Auth

Module SymSvel (manifest schema 1).

Le module Auth ne fournit qu'un composant `back`. Il porte l'authentification des contextes BO et, lorsque l'App est installée, App, sans posséder d'écrans Svelte propres.

Les interfaces de connexion relèvent des composants BO et App correspondants. Les modalités techniques d'intégration à Symfony Security restent à définir après audit des modules existants et validation architecturale.

## Sécurité des connexions BO

Dans la distribution standard, `symsvel-framework/module-two-factor` est installé automatiquement. Après authentification du mot de passe, chaque nouvelle connexion BO exige un challenge TOTP. Si le provider de second facteur manque ou n'émet pas de challenge, Auth échoue sans créer de session. L'App conserve une politique facultative ; Google/OIDC est réservé à l'App et n'est pas fourni par ce module. Voir `docs/dev/authentication.md`.
