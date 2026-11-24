import { passwordStrength } from '../../password/strength';
import { generatedTranslation } from '../../i18n/generated-translations';

export function validInvitationToken(token: string | null): token is string {
  return typeof token === 'string' && /^[A-Za-z0-9_-]{43}$/.test(token);
}

export function validInvitationPassword(password: string): boolean {
  return passwordStrength(password).valid;
}

const messages = {
  fr: {
    title: 'Activer mon compte administrateur',
    introduction: 'Créez votre mot de passe pour confirmer votre adresse e-mail.',
    password: 'Nouveau mot de passe',
    confirmation: 'Confirmer le mot de passe',
    minimum: '12 caractères minimum, majuscule, minuscule, chiffre et caractère spécial.',
    strength: 'Force du mot de passe (indicative)',
    strengthHint: 'Une phrase longue et variée est recommandée.',
    strengthLevels: ['Aucune saisie', 'Très faible', 'Faible', 'Moyenne', 'Bonne'],
    submit: 'Activer mon compte',
    busy: 'Activation…',
    done: 'Votre compte est activé. Vous pouvez maintenant vous connecter.',
    login: 'Aller à la connexion',
    mismatch: 'Les deux mots de passe ne correspondent pas.',
    invalidPassword: 'Respectez les critères du nouveau mot de passe.',
    invalidToken: 'Lien d’invitation invalide ou manquant.',
    expired: 'Ce lien est invalide, expiré ou déjà utilisé.',
    failure: 'L’activation est momentanément impossible.'
  },
  en: {
    title: 'Activate administrator account',
    introduction: 'Set a password to verify your email address.',
    password: 'New password',
    confirmation: 'Confirm password',
    minimum: 'At least 12 characters, uppercase, lowercase, digit and special character.',
    strength: 'Password strength (estimate)',
    strengthHint: 'A long passphrase with varied characters is recommended.',
    strengthLevels: ['Empty', 'Very low', 'Low', 'Moderate', 'Good'],
    submit: 'Activate account',
    busy: 'Activating…',
    done: 'Your account is now active. You can sign in.',
    login: 'Go to sign in',
    mismatch: 'Passwords do not match.',
    invalidPassword: 'Meet the new password requirements.',
    invalidToken: 'Invitation link is missing or invalid.',
    expired: 'This link is invalid, expired or has already been used.',
    failure: 'Account activation is currently unavailable.'
  }
};
export type InvitationActivationCopy = typeof messages.fr;
export function invitationActivationCopy(language: string | null): InvitationActivationCopy {
  const base = language?.toLowerCase().split('-')[0] === 'en' ? messages.en : messages.fr;
  return Object.fromEntries(Object.entries(base).map(([key, value]) => [
    key, Array.isArray(value)
      ? value.map((entry, index) => generatedTranslation(language, 'bo.auth.' + key + '.' + index) ?? entry)
      : generatedTranslation(language, 'bo.auth.' + key) ?? value
  ])) as InvitationActivationCopy;
}
