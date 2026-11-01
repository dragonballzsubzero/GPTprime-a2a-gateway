// SAC admin sign-in MFA client. Auth requests go directly to Supabase Auth.
// All tokens/QR secrets stay in volatile browser memory. No persistence or logs.
const idPattern = /^[a-f0-9-]{36}$/i;
function reject(message) { throw new Error(message); }
export function createMfaClient(settings, token, transport = fetch) {
  if (!/^https:\/\/[a-z0-9-]+\.supabase\.co$/.test(settings?.url || '')) reject('INVALID_AUTH_ORIGIN');
  if (typeof settings.publishableKey !== 'string' || !settings.publishableKey.startsWith('sb_publishable_')) reject('INVALID_PUBLIC_KEY');
  if (typeof token !== 'string' || token.length < 24) reject('INVALID_AUTH_TOKEN');
  async function request(path, method = 'GET', body) {
    const res = await transport(settings.url + path, {
      method,
      headers: {apikey: settings.publishableKey, Authorization: 'Bearer ' + token,
        ...(body !== undefined ? {'Content-Type':'application/json'} : {})},
      ...(body !== undefined ? {body: JSON.stringify(body)} : {}),
    });
    let result = {};
    try { result = await res.json(); } catch { /* hide untrusted server body */ }
    if (!res.ok) reject(result.error_description || result.msg || result.message || result.error || 'AUTH_REQUEST_FAILED');
    return result;
  }
  return {
    async verifiedTotpFactors() {
      const user = await request('/auth/v1/user');
      return (Array.isArray(user.factors) ? user.factors : [])
        .filter(x => x.factor_type === 'totp' && x.status === 'verified' && idPattern.test(x.id || ''))
        .map(x => ({id:x.id, label:x.friendly_name || 'Authenticator app'}));
    },
    async enrollTotp() {
      const result = await request('/auth/v1/factors', 'POST', {factor_type:'totp',friendly_name:'SAC Mainframe Admin'});
      if (!idPattern.test(result.id || '') || !result.totp?.secret) reject('INVALID_ENROLL_RESPONSE');
      return {id:result.id, qrCode:result.totp.qr_code || '', secret:result.totp.secret};
    },
    async challengeAndVerify(factorId, code) {
      if (!idPattern.test(factorId || '') || !/^\d{6}$/.test(code || '')) reject('INVALID_MFA_CHALLENGE');
      const challenge = await request(`/auth/v1/factors/${factorId}/challenge`, 'POST', {});
      if (!idPattern.test(challenge.id || '')) reject('INVALID_CHALLENGE_RESPONSE');
      const result = await request(`/auth/v1/factors/${factorId}/verify`, 'POST', {challenge_id:challenge.id,code});
      if (!result.access_token || !result.refresh_token) reject('INVALID_MFA_SESSION');
      return result;
    }
  };
}