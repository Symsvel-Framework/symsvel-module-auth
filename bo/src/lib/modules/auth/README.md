# Auth (bo)

Point d'intégration SvelteKit du module. Importer les composants et services ici ; aucune route applicative n'est imposée.

## Activation publique d'une invitation BO (16/11/2026)

Le manifeste Auth déclare désormais le composant obligatoire BO, synchronisé par Tooling. La page `bo/src/routes/auth/activate/+page.svelte` devient `/auth/activate` dans le BO assemblé, à configurer comme valeur serveur de `auth.bo_invitation_url` (HTTPS, sans query string). Cette route est **publique** : aucune session préalable n'est requise. Elle ne fait aucun appel de login implicite.

Le secret `?token=...` est extrait au chargement, strictement validé, puis effacé de la barre d'adresse et de l'historique avant toute action de l'utilisateur ; le formulaire le conserve uniquement en mémoire. Les mots de passe sont saisis deux fois et validés (12 à 1024 octets, sans octet nul). `POST /apibo/auth/invitation/complete` passe par `api(..., {public:true})` : **pas de Bearer, cookie, ni session enregistrée**. Le backend consomme le jeton, valide l'adresse et enregistre le mot de passe atomiquement, puis la vue dirige vers `/login`.

Les textes FR/EN sont externalisés dans `bo/src/lib/modules/auth/invitation.ts`, comme les autres messages du BO. Aucun jeton n'est journalisé ni copié en stockage persistant. Les tests Vitest couvrent la validité du jeton, les mots de passe et l'i18n. Build Svelte assemblé et CT HTTP restent obligatoires.

### Résolution effective des imports Svelte (16/11/2026)

Le `svelte-check` du BO hôte ne résout pas les alias `#lib` et `$lib` depuis les pages modules copiées par Tooling avec la configuration TypeScript actuelle. La page utilise donc des **imports relatifs à sa destination synchronisée** sous `src/lib/modules/…/routes/`, suivant le modèle déjà opérationnel des pages de connexion et dashboard du BO. Le relais de route généré par Tooling demeure inchangé. Le CI `bo-integration` teste la résolution dans le vrai BO assemblé.
