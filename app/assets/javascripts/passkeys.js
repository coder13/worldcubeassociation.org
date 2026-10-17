/* jshint esversion: 11, browser: true */
/* globals PublicKeyCredential, FormData, fetch */

// Rails still serves the sign-in and account pages. Keep both ceremonies on
// that origin and use the browser's WebAuthn JSON conversion methods.
document.querySelectorAll('[data-passkey-form]').forEach(function (form) {
  'use strict';

  var button = form.querySelector('[data-passkey-submit]');
  var errorElement = form.querySelector('[data-passkey-error]');
  var statusElement = form.querySelector('[data-passkey-status]');
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
    if (!response.ok) {
      var problem = await response.json();
      var error = new Error('Passkey request failed');
      error.userMessage = problem.error && problem.error.message;
      throw error;
    }
    return response.json();
  }

  form.addEventListener('submit', async function (event) {
    event.preventDefault();
    if (button.disabled) { return; }
    button.disabled = true;
    errorElement.textContent = '';
    var registration = form.dataset.passkeyForm === 'registration';
    statusElement.textContent = registration ? form.dataset.checking : form.dataset.waiting;
    var fields = Object.fromEntries(new FormData(form));

    try {
      var options = await postJSON(form.dataset.optionsUrl, {
        password: fields.password,
        otp_attempt: fields.otp_attempt
      });
      statusElement.textContent = form.dataset.waiting;
      var publicKey = registration ?
        PublicKeyCredential.parseCreationOptionsFromJSON(options) :
        PublicKeyCredential.parseRequestOptionsFromJSON(options);
      var credential = registration ?
        await navigator.credentials.create({ publicKey: publicKey }) :
        await navigator.credentials.get({ publicKey: publicKey });
      statusElement.textContent = form.dataset.saving;
      var result = await postJSON(form.action, {
        name: fields.name,
        credential: credential.toJSON()
      });
      window.location.assign(result.redirect_url);
    } catch (error) {
      statusElement.textContent = '';
      errorElement.textContent = error.name === 'NotAllowedError' ?
        form.dataset.cancelled : error.name === 'InvalidStateError' && registration ?
        form.dataset.duplicate : error.userMessage || form.dataset.error;
      errorElement.focus();
    } finally {
      form.querySelectorAll('input[type="password"], input[name="otp_attempt"]').forEach(function (input) {
        input.value = '';
      });
      button.disabled = false;
    }
  });
});
