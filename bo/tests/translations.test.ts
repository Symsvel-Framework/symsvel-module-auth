import { describe, expect, it } from 'vitest';
import fr from '../src/lib/translations/fr';
import en from '../src/lib/translations/en';

describe('Auth BO dictionaries', () => {
  it('aligns FR/EN labels', () => {
    expect(Object.keys(fr).sort()).toEqual(Object.keys(en).sort());
    expect(fr.session.logout).toBe('Déconnexion');
    expect(en.session.checking).toBe('Checking session…');
    expect(fr.title).toBe('Activer mon compte administrateur');
    expect(fr.signIn.title).toBe('Connexion');
    expect(en.signIn.title).toBe('Sign in');
  });
});
