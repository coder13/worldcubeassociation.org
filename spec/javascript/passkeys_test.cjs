const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const vm = require('node:vm');

const source = readFileSync('app/assets/javascripts/passkeys.js', 'utf8');

function browser({ ceremony = 'authentication', supported = true, cancel = false, fail = false } = {}) {
  const button = { disabled: true };
  const error = { textContent: '' };
  const unsupported = { hidden: false };
  const password = { value: 'current password' };
  const otp = { value: '123456' };
  const requests = [];
  const redirects = [];
  const calls = [];
  const form = {
    action: '/passkeys/finish',
    dataset: { passkeyForm: ceremony, optionsUrl: '/passkeys/options', error: 'Request failed', cancelled: 'Cancelled' },
    querySelector(selector) {
      return {
        '[data-passkey-submit]': button,
        '[data-passkey-error]': error,
        '[data-passkey-unsupported]': unsupported,
        '[name="authenticity_token"]': { value: 'csrf token' },
      }[selector];
    },
    querySelectorAll() { return [password, otp]; },
    addEventListener(event, handler) { this.submit = handler; },
  };
  class PublicKeyCredential {
    static parseCreationOptionsFromJSON(options) { calls.push('parse creation'); return options; }
    static parseRequestOptionsFromJSON(options) { calls.push('parse request'); return options; }
    toJSON() { return { id: 'credential', type: 'public-key' }; }
  }
  const credentials = (method) => async (options) => {
    calls.push(method);
    assert.equal(options.publicKey.challenge, 'challenge');
    if (cancel) { throw Object.assign(new Error(), { name: 'NotAllowedError' }); }
    return new PublicKeyCredential();
  };
  vm.runInNewContext(source, {
    window: { isSecureContext: supported, PublicKeyCredential, location: { assign: (url) => redirects.push(url) } },
    PublicKeyCredential,
    document: { querySelectorAll: () => [form] },
    navigator: { credentials: { create: credentials('create'), get: credentials('get') } },
    FormData: class { constructor() { return Object.entries({ name: 'My laptop', password: password.value, otp_attempt: otp.value }); } },
    fetch: async (url, request) => {
      requests.push({ url, ...request, body: JSON.parse(request.body) });
      return { ok: !fail, json: async () => url === form.dataset.optionsUrl ? { challenge: 'challenge' } : { redirect_url: '/account' } };
    },
  });
  return { form, button, error, unsupported, password, otp, requests, redirects, calls };
}

test('unsupported browsers retain a disabled passkey button', () => {
  const page = browser({ supported: false });
  assert.equal(page.button.disabled, true);
  assert.equal(page.unsupported.hidden, false);
  assert.equal(page.form.submit, undefined);
});

test('registration sends current credentials only to the options endpoint', async () => {
  const page = browser({ ceremony: 'registration' });
  await page.form.submit({ preventDefault() {} });
  assert.deepEqual(page.calls, ['parse creation', 'create']);
  assert.deepEqual(page.requests[0].body, { password: 'current password', otp_attempt: '123456' });
  assert.deepEqual(page.requests[1].body, { name: 'My laptop', credential: { id: 'credential', type: 'public-key' } });
  assert.equal(page.requests[0].headers['X-CSRF-Token'], 'csrf token');
  assert.equal(page.requests[0].credentials, 'same-origin');
  assert.deepEqual(page.redirects, ['/account']);
  assert.equal(page.password.value, '');
  assert.equal(page.otp.value, '');
});

test('sign-in requests a credential and redirects after verification', async () => {
  const page = browser();
  await page.form.submit({ preventDefault() {} });
  assert.deepEqual(page.calls, ['parse request', 'get']);
  assert.deepEqual(page.redirects, ['/account']);
  assert.equal(page.button.disabled, false);
});

test('cancellation shows a retry message and clears secrets', async () => {
  const page = browser({ cancel: true });
  await page.form.submit({ preventDefault() {} });
  assert.equal(page.error.textContent, 'Cancelled');
  assert.equal(page.requests.length, 1);
  assert.equal(page.button.disabled, false);
  assert.equal(page.password.value, '');
  assert.deepEqual(page.redirects, []);
});

test('server rejection shows an error without starting WebAuthn', async () => {
  const page = browser({ fail: true });
  await page.form.submit({ preventDefault() {} });
  assert.equal(page.error.textContent, 'Request failed');
  assert.deepEqual(page.calls, []);
  assert.deepEqual(page.redirects, []);
});

test('a second submit cannot start another pending ceremony', async () => {
  const page = browser();
  await Promise.all([page.form.submit({ preventDefault() {} }), page.form.submit({ preventDefault() {} })]);
  assert.equal(page.requests.length, 2);
  assert.deepEqual(page.calls, ['parse request', 'get']);
});
