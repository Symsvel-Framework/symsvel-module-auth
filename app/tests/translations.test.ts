import { describe, expect, it } from 'vitest';
import fr from '../src/lib/translations/fr';
import en from '../src/lib/translations/en';

describe('Auth App dictionaries', () => {
  it('aligns FR/EN labels', () => {
    expect(Object.keys(fr).sort()).toEqual(Object.keys(en).sort());
    expect(fr.signIn).toBe('Connexion');
    expect(Object.hasOwn(fr, 'dashboard')).toBe(false);
    expect(Object.hasOwn(en, 'loggedIn')).toBe(false);
  });
});
