import { describe, expect, it } from 'vitest';
import { moduleId } from '../src/lib/modules/auth';

describe('auth module', () => {
  it('exports its identifier', () => {
    expect(moduleId).toBe('auth');
  });
});
