<script lang="ts">
  import { getProjectBrand } from '../../../../../branding';
  const brandName = getProjectBrand();
  import { onMount } from 'svelte';
  import { resolve } from '$app/paths';
  import { ApiError, api } from '../../../../../api/client';
  import { uiLanguage } from '../../../../../api/locales';
  import { passwordStrength } from '../../../../../password/strength';
  import {
    invitationActivationCopy, validInvitationToken, validInvitationPassword
  } from '../../../invitation';

  let token = $state<string | null>(null);
  let loaded = $state(false);
  let completed = $state(false);
  let busy = $state(false);
  let password = $state('');
  let confirmation = $state('');
  let error = $state('');
  const language = $derived($uiLanguage ?? (typeof navigator === 'undefined' ? 'en' : navigator.language));
  const t = $derived(invitationActivationCopy(language));
  const strength = $derived(passwordStrength(password));

  onMount(() => {
    const candidate = new URLSearchParams(window.location.search).get('token');
    token = validInvitationToken(candidate) ? candidate : null;
    // The link is a one-time secret; avoid exposing it in navigation history and referrers.
    window.history.replaceState(window.history.state, '', window.location.pathname + window.location.hash);
    loaded = true;
  });

  async function activate(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (busy || !token) return;
    error = '';
    if (password !== confirmation) {
      error = t.mismatch;
      return;
    }
    if (!validInvitationPassword(password)) {
      error = t.invalidPassword;
      return;
    }
    busy = true;
    try {
      await api<{ status: 'completed' }>('/apibo/auth/invitation/complete', {
        method: 'POST',
        public: true,
        body: JSON.stringify({ token, password })
      });
      completed = true;
      token = null;
      password = '';
      confirmation = '';
    } catch (cause) {
      error = cause instanceof ApiError && cause.status === 400 ? t.expired : t.failure;
    } finally {
      busy = false;
    }
  }
</script>

<svelte:head>
  <title>{t.title} | {$brandName} BO</title>
  <meta name="referrer" content="no-referrer" />
</svelte:head>

<main class="auth-shell">
  <section class="auth-card" aria-labelledby="invitation-activation-title">
    <header><strong>{$brandName}</strong><span>BO</span></header>
    <h1 id="invitation-activation-title">{t.title}</h1>
    {#if completed}
      <p role="status">{t.done}</p>
      <p><a href={resolve('/login')}>{t.login}</a></p>
    {:else if loaded && !token}
      <p class="alert" role="alert">{t.invalidToken}</p>
    {:else if loaded}
      <p>{t.introduction}</p>
      {#if error}<p class="alert" role="alert">{error}</p>{/if}
      <form class="form" onsubmit={activate}>
        <label for="invitation-password">{t.password}</label>
        <input id="invitation-password" type="password" autocomplete="new-password"
          bind:value={password} maxlength="1024" required />
        <small>{t.minimum}</small>
        <meter min="0" max="4" value={strength.score} aria-label={t.strength}></meter>
        <small aria-live="polite">{t.strength}: {t.strengthLevels[strength.score]}</small>
        <small>{t.strengthHint}</small>
        <label for="invitation-confirm">{t.confirmation}</label>
        <input id="invitation-confirm" type="password" autocomplete="new-password"
          bind:value={confirmation} maxlength="1024" required />
        <button type="submit" disabled={busy}>{busy ? t.busy : t.submit}</button>
      </form>
    {/if}
  </section>
</main>

<style>
  meter { display: block; width: 100%; height: 13px; }
  small { color: var(--bo-muted); }
</style>
