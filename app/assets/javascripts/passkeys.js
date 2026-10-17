/* jshint esversion: 11, browser: true */
/* globals PublicKeyCredential, FormData, fetch */

// Rails still serves the sign-in and account pages. Keep both ceremonies on
// that origin and use the browser's WebAuthn JSON conversion methods.
document.querySelectorAll('[data-passkey-form]').forEach(function (form) {
  'use strict';

  var button = form.querySelector('[data-passkey-submit]');
  var errorElement = form.querySelector('[data-passkey-error]');
  var supported = window.isSecureContext && window.PublicKeyCredential &&
    typeof PublicKeyCredential.parseCreationOptionsFromJSON === 'function' &&
    typeof PublicKeyCredential.parseRequestOptionsFromJSON === 'function' &&
    typeof PublicKeyCredential.prototype.toJSON === 'function';

  if (!supported) { return; }
  button.disabled = false;
  form.querySelector('[data-passkey-unsupported]').hidden = true;

  async function postJSON(url, body) {
    var response = await fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        // A form token only covers its action. Both ceremony endpoints need
        // the page token from Rails' csrf_meta_tags.
        'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]').content
      },
      body: JSON.stringify(body)
    });
    if (!response.ok) { throw new Error('Passkey request failed'); }
    return response.json();
  }

  form.addEventListener('submit', async function (event) {
    event.preventDefault();
    if (button.disabled) { return; }
    button.disabled = true;
    errorElement.textContent = '';
    var fields = Object.fromEntries(new FormData(form));

    try {
      var options = await postJSON(form.dataset.optionsUrl, {
        password: fields.password,
        otp_attempt: fields.otp_attempt
      });
      var registration = form.dataset.passkeyForm === 'registration';
      var publicKey = registration ?
        PublicKeyCredential.parseCreationOptionsFromJSON(options) :
        PublicKeyCredential.parseRequestOptionsFromJSON(options);
      var credential = registration ?
        await navigator.credentials.create({ publicKey: publicKey }) :
        await navigator.credentials.get({ publicKey: publicKey });
      var result = await postJSON(form.action, {
        name: fields.name,
        credential: credential.toJSON()
      });
      window.location.assign(result.redirect_url);
    } catch (error) {
      errorElement.textContent = error.name === 'NotAllowedError' ?
        form.dataset.cancelled : form.dataset.error;
    } finally {
      form.querySelectorAll('input[type="password"], input[name="otp_attempt"]').forEach(function (input) {
        input.value = '';
      });
      button.disabled = false;
    }
  });
});
