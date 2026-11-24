import { describe, expect, it } from 'vitest';
import { moduleId } from '../src/lib/modules/auth';
import {
  invitationActivationCopy,
  validInvitationPassword,
  validInvitationToken
} from '../src/lib/modules/auth/invitation';

describe('auth module', () => {
  it('exports its identifier', () => {
    expect(moduleId).toBe('auth');
  });
  it('rejects malformed invitation tokens', () => {
    expect(validInvitationToken('A'.repeat(43))).toBe(true);
    expect(validInvitationToken('bad')).toBe(false);
    expect(validInvitationToken(null)).toBe(false);
    expect(validInvitationToken('A'.repeat(42) + '?')).toBe(false);
  });
  it('enforces the new-password policy', () => {
    expect(validInvitationPassword('Abcdefghij1!')).toBe(true);
    expect(validInvitationPassword('a'.repeat(12))).toBe(false);
    expect(validInvitationPassword('short')).toBe(false);
    expect(validInvitationPassword('a'.repeat(1025))).toBe(false);
    expect(validInvitationPassword('long-password\0no')).toBe(false);
  });
  it('externalizes French and English labels', () => {
    expect(invitationActivationCopy('fr-FR').submit).toBe('Activer mon compte');
    expect(invitationActivationCopy('en-GB').submit).toBe('Activate account');
    expect(invitationActivationCopy('es-ES').submit).toBe('Activer mon compte');
  });
});
