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


### Tests de distribution (16/11/2026)

Les tests d'envoi `PasswordResetDispatchTest` et
`EmailVerificationDispatchTest` utilisent à présent la génération
d'URL basée sur le domaine runtime, sans paramètres Auth en BDD.
Ils sélectionnent explicitement `mails.transport=mailpit`, conformément
au nouvel envoi sans fallback de Mails. Les scénarios de domaine
manquant échouent avant toute réservation de quota ou recherche de compte.


### Schéma des liens en développement local (16/11/2026)

Sans origine de déploiement explicite, `AuthPageUrls` choisit
`http://` pour les domaines de Setup terminant en `.localhost`,
`.local` ou `.test` lorsque `APP_ENV=dev`. Les autres domaines
et les environnements de production restent en HTTPS. Le développeur
peut forcer une origine HTTPS locale via la configuration de
déploiement `SYMSVEL_BO_ORIGIN` / `SYMSVEL_APP_ORIGIN`.
Le choix ne dépend jamais du `Host` de la requête reçue.


### Origines explicites de production sans domaine local (16/11/2026)

Une origine HTTPS de déploiement fournie explicitement par
`SYMSVEL_BO_ORIGIN` ou `SYMSVEL_APP_ORIGIN` est suffisante pour le
contexte concerné. En production, ce cas ne nécessite pas de recopier
`SYMSVEL_BO_DOMAIN` depuis le Setup local. Le domaine de base reste
obligatoire si le contexte n'a aucune origine explicite et pour
valider les dérogations HTTP de développement. La configuration
continue de refuser chemins, credentials et query strings.

## Fallback des libellés BO (17/11/2026)

Les libellés français sont la valeur de repli lorsque la langue d'interface n'a pas encore de traduction disponible ; l'anglais reste servi pour `en`. Les codes ISO enregistrés en base ne changent pas. Cette correction ne crée pas d'éditeur de traductions ni de lecteur de fichiers dynamiques ; le déploiement d'un tel mécanisme relève du chantier i18n dédié. Tests FR, EN et locale non traduite ajoutés ; CI et crash-test local à confirmer.


## Dictionnaires Auth BO et App (18/11/2026)

Auth est propriétaire des textes d'authentification des deux interfaces. Les fichiers `bo/src/lib/translations/<lang>.ts` et `app/src/lib/translations/<lang>.ts` fournissent les valeurs FR/EN, y compris les listes de robustesse via des clés numériques `strengthLevels.0` etc. Tooling les installe en `lib/translations/auth/<lang>.ts`, puis les persiste dans Languages avec les clés `bo.auth.*` et `app.auth.*`. Les écrans hôtes restent consommateurs et ne deviennent pas propriétaires de ces chaînes. CI et CT XT requis.


### Connexion native du BO (18/11/2026)

La page `/login` est hébergée dans le Svelte BO, mais ses libellés fonctionnels appartiennent au module Auth. Le module fournit des clés `bo.auth.signIn.*` dans ses dictionnaires BO FR/EN. La clé ancienne `bo.auth.login` du formulaire d'activation reste distincte, afin d'éviter tout conflit texte/objet avec `bo.auth.signIn.*`. Aucun texte de connexion n'est attribué à `bo.system`.


### Dashboard App : séparation des propriétaires

Les libellés du tableau de bord générique (`dashboard`, `loggedIn`) ont été retirés des dictionnaires Auth et placés sous `app.system.dashboard.*` dans le Svelte App. Les fonctions de connexion, récupération et déconnexion restent des clés `app.auth.*`. Les textes de repli historiques du helper Auth sont temporairement conservés pour les projets non encore synchronisés.
