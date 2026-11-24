# Invitation et activation des utilisateurs App (16 novembre 2026)

Le parcours BO de création d'utilisateur est une **invitation**, sans saisie
du mot de passe du destinataire. La fonctionnalité appartient à Users,
Auth gère le jeton à usage unique et Mails expédie le message FR/EN.
Auth n'importe pas Users ; son interface optionnelle
`AppInvitationIdentity` est fournie par le module propriétaire.

La migration Schema additive `Version20261116000506` crée
`symsvel_auth_app_invitations`, indépendante des tables BO,
de confirmation d'email et de récupération de mot de passe.
Le jeton de 256 bits est hashé, limité à une heure, lié à l'empreinte
de l'adresse enregistrée et consommé en transaction DBAL.
En cas de rejet du compte, la consommation est annulée.

Le lien d'invitation App est calculé par `AuthPageUrls` depuis l'origine
explicite `SYMSVEL_APP_ORIGIN` fournie par le mapping des URL du Setup,
suivie du chemin fixe `/activate`. Par exemple, le scope logique `app`
peut correspondre à `https://manager.choralys.com`. Lorsque le mapping
n'est pas configuré (anciens projets), `SYMSVEL_BO_DOMAIN` conserve son
rôle de base de domaine historique et produit `app.<domaine>`.
Aucune URL d'activation n'est éditable dans Settings ni dérivée du navigateur BO. Le template
`auth.app.user_invitation` comporte les langues FR/EN. L'activation App
envoie `POST /apiopen/auth/invitation/complete` avec le jeton et
le nouveau mot de passe (12 à 1024 octets, Argon2id côté propriétaire).

L'activation confirme aussi la boîte mail en même temps que le mot de
passe, sans créer de session implicite. Aucun token BO, de reset ou de
vérification d'email n'est interchangeable. Les tests et la CI ne
remplacent pas le crash-test XT réel avec SMTP et multi-SGBD.
