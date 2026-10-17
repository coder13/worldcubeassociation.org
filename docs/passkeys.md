# Passkey proof of concept

This change adds optional passkey sign-in to the Rails website. It is disabled by default.

## Try the feature

1. Install the dependencies with `bin/bundle install`.
2. Run `bin/rails db:migrate`.
3. Set `PASSKEYS_ENABLED=true`.
4. Set `ROOT_URL` to the exact origin of the Rails website, such as `http://localhost:3000`.
5. Restart Rails.
6. Sign in with a password.
7. Open **Edit profile**, then **Passkeys**.
8. Select **Create a passkey**.
9. Enter the current password and a two-factor code if the account requires one.
10. Select **Create a passkey**, then complete the browser prompt.
11. Keep the suggested name or save a name of your own.
12. Select **Done**, then sign out.
13. Select **Sign in with a passkey** on the sign-in page.

The settings page lists passkeys without password fields. Each card links to rename and delete pages.
Deletion explains the effect, shows the fallback sign-in method for the last passkey, and requires identity confirmation.
The [UX decision](passkeys-ux.md) compares the alternatives and links to the design guidance.

The browser requires HTTPS, except on localhost. This prototype requires the native WebAuthn JSON methods.
Unsupported browsers retain the password form. The classic and redesigned Rails sign-in pages use the same passkey form.

## Security behavior

- Registration requires the current password and an enabled two-factor code or backup code.
- Registration requests a discoverable credential and requires user verification.
- Sign-in requires a signature, user presence, and user verification. A PIN or biometric check unlocks the passkey.
- A verified passkey replaces password plus OTP for that sign-in. Password sign-in retains the existing OTP requirement.
- The server matches the returned user handle to the credential owner and enforces Devise account status.
- A deployment-controlled origin and RP ID separate development, staging, and production credentials.
- The server rejects cross-origin iframe ceremonies.
- A challenge expires after five minutes. An atomic database delete consumes each challenge before verification.
- A challenge belongs to one browser session, one ceremony, and the account that authorized registration.
- Starting another ceremony replaces the pending challenge in that session. Concurrent tabs must retry.
- Row locks serialize the signature counter update. Authenticators with a constant zero counter remain supported.
- Sign-in resets the session, invokes Devise authentication hooks, and preserves the stored return location.
- Deletion requires the current password and an enabled two-factor code. Users can delete only their own passkeys.
- All state-changing requests require CSRF protection. Authentication responses disable caching. Production requests have rate limits.
- The authenticator keeps the private key. The server stores the public key.
- Developer exports exclude credentials and challenges and clear user handles.

## Boundaries before rollout

This prototype does not change session duration, enforce MFA by role, or add passkey step-up for other actions.
Passkey sign-in creates a normal session. It does not select **Remember me**.
Password reset remains the recovery path. Passkey-only accounts and a new recovery policy are outside this change.
Deletion blocks future sign-ins with that credential. Existing sessions remain valid and use the existing session revocation control.

Before rollout, review recovery assurance, security notifications, credential limits, and passkey-based account management.
Also review the decision to accept a verified passkey instead of an OTP for accounts with two-factor authentication.
Check real devices, synced passkeys, cross-device sign-in, accessibility, and deployment origin settings.
Challenges expire during the next ceremony request. A scheduled cleanup can remove expired rows during periods without requests.

## Checks

Run the server checks with `bin/rspec spec/requests/passkeys_spec.rb spec/models/passkey_challenge_spec.rb`.
Run the browser adapter checks with `node --test spec/javascript/passkeys_test.cjs`.

## References

- [WebAuthn server library](https://github.com/cedarcode/webauthn-ruby)
- [WebAuthn specification](https://www.w3.org/TR/webauthn-3/)
- [OWASP MFA guidance](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)
