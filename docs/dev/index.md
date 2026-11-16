# Auth

Documentation développeur.


## Formulaire d'activation BO (16/11/2026)

La jauge de robustesse native se déclare avec une balise HTML complète
`<meter></meter>` pour respecter la syntaxe Svelte. Elle conserve son score
et ses textes existants ; aucune modification d'authentification ni de
contrat d'activation n'est introduite.


## URL des pages d'authentification dérivées du Setup (16/11/2026)

Les cinq anciennes définitions Settings `auth.bo_reset_url`,
`auth.app_reset_url`, `auth.bo_verify_email_url`,
`auth.bo_invitation_url` et `auth.app_invitation_url` ne sont plus
éditables. Un provider Auth vide est conservé temporairement afin que
`symsvel:settings:sync` puisse retirer les cinq clés du catalogue/BDD
selon l'ADR cycle de vie des paramètres. Un `AuthPageUrls` commun
construit tous les liens à partir de `SYMSVEL_BO_DOMAIN` publié par
Setup ou Tooling, sans ouvrir `.symsvel/project.json` depuis PHP-FPM et
sans confiance dans `Host` HTTP. App et BO possèdent chacun leurs routes.

Par défaut, l'origine est `https://bo.<domaine>` ou
`https://app.<domaine>`. Pour un hébergement aux domaines différents,
les variables de déploiement `SYMSVEL_BO_ORIGIN` (déjà utilisée par
`TrustedBoOrigin`) et `SYMSVEL_APP_ORIGIN` peuvent fixer les origines
complètes. Elles exigent HTTPS en production, sans chemins, requêtes ou
identifiants. En `dev`, une origine HTTP explicite est autorisée
uniquement pour le sous-domaine du projet enregistré par Setup.
Aucune URL arbitraire ne peut être sauvée depuis le BO.

Les pages BO de récupération et de vérification doivent être
présentes dans l'interface hôte avant qu'un mail y conduisant soit
émis ; cette passe fixe la génération d'URL, sans présumer de la
disponibilité des pages UI. La QA couvre les origines et refus
de domaines malformés, et le CT XT doit confirmer les parcours.
