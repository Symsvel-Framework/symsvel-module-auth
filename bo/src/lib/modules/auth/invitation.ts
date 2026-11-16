export function validInvitationToken(token: string | null): token is string {
  return typeof token === 'string' && /^[A-Za-z0-9_-]{43}$/.test(token);
}

export function validInvitationPassword(password: string): boolean {
  const size = new TextEncoder().encode(password).length;
  return size >= 12 && size <= 1024 && !password.includes('\0');
}

const messages = {
  fr: {
    title: 'Activer mon compte administrateur',
    introduction: 'Créez votre mot de passe pour confirmer votre adresse e-mail.',
    password: 'Nouveau mot de passe',
    confirmation: 'Confirmer le mot de passe',
    minimum: 'De 12 à 1024 octets UTF-8, sans caractère nul.',
    strength: 'Diversité du mot de passe',
    strengthHint: 'Une phrase longue et variée est recommandée.',
    strengthLevels: ['Aucune saisie', 'Très faible', 'Faible', 'Moyenne', 'Bonne'],
    submit: 'Activer mon compte',
    busy: 'Activation…',
    done: 'Votre compte est activé. Vous pouvez maintenant vous connecter.',
    login: 'Aller à la connexion',
    mismatch: 'Les deux mots de passe ne correspondent pas.',
    invalidPassword: 'Choisissez un mot de passe valide de 12 caractères minimum.',
    invalidToken: 'Lien d’invitation invalide ou manquant.',
    expired: 'Ce lien est invalide, expiré ou déjà utilisé.',
    failure: 'L’activation est momentanément impossible.'
  },
  en: {
    title: 'Activate administrator account',
    introduction: 'Set a password to verify your email address.',
    password: 'New password',
    confirmation: 'Confirm password',
    minimum: '12 to 1024 UTF-8 bytes, no NUL character.',
    strength: 'Password diversity',
    strengthHint: 'A long passphrase with varied characters is recommended.',
    strengthLevels: ['Empty', 'Very low', 'Low', 'Moderate', 'Good'],
    submit: 'Activate account',
    busy: 'Activating…',
    done: 'Your account is now active. You can sign in.',
    login: 'Go to sign in',
    mismatch: 'Passwords do not match.',
    invalidPassword: 'Choose a valid password with at least 12 characters.',
    invalidToken: 'Invitation link is missing or invalid.',
    expired: 'This link is invalid, expired or has already been used.',
    failure: 'Account activation is currently unavailable.'
  }
};
export type InvitationActivationCopy = typeof messages.fr;
export function invitationActivationCopy(language: string | null): InvitationActivationCopy {
  return language?.toLowerCase().split('-')[0] === 'fr' ? messages.fr : messages.en;
}
