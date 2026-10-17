# Passkey UX decision

Use a dedicated creation page, with optional naming after the browser finishes.
This is a design choice for WCA, rather than a universal requirement from FIDO.

## Options considered

| Option | Benefit | Cost | Decision for WCA |
| --- | --- | --- | --- |
| Always show name and password fields in settings | Few page transitions | Adds sensitive forms to a page used mainly to review credentials | Replace |
| Expand an inline creation form | Keeps the list nearby | Requires extra state and focus handling when browser prompts open and close | Reasonable alternative |
| Open a modal or drawer | Keeps the settings context | Competes with the browser prompt and needs focus restoration and mobile scroll handling | Do not add another dialog layer |
| Open a dedicated creation page | Gives identity confirmation and browser instructions a clear place | Adds one navigation step | Selected |
| Open the browser prompt directly from the list | Fast after recent authentication | Needs an action-bound authorization flow and recovery from cancellation | Revisit with shared step-up authentication |
| Prompt after sign-in or account recovery | Reaches users during an account task | Needs rollout rules and a clear opt-out | Future adoption work |

FIDO places creation and management in account settings. It recommends clear messages before and after browser prompts.
Google recommends a presentation that matches the existing product. Neither source requires a modal or a separate page.
GitHub provides a useful deployed example: settings action, identity confirmation, browser prompt, and success page.

## Selected flow

1. In **Passkeys**, select **Create a passkey**.
2. On the creation page, confirm the current password and any required two-factor code.
3. Select **Create a passkey** to open the browser prompt.
4. After the server saves the credential, show success and an optional name field.
5. Save a name or select **Done**. Return to the passkey list.

The setup page identifies the account and explains where the browser can save the passkey.
It does not ask users to choose a storage provider before the browser presents its own choices.
The current password and OTP policy stays unchanged. This change does not introduce a reusable authorization window.

## Names and storage

Required naming before creation adds a decision before the user knows where the passkey will live.
The default name is **Passkey 1**, then the next available number. Users can rename it after creation or later.
The name field is optional. Blank input keeps the existing name.

A browser or device name does not prove where a passkey is stored or which devices can use it.
The UI therefore avoids guessed provider names and device-only claims.
Provider identification through AAGUID metadata is a possible later improvement, with a generic fallback for unknown providers.
The site nickname does not rename the saved entry in the user's password manager.

## Management, errors, and access

- Keep a short explanation visible, including after the first passkey exists.
- Show one card per credential, with its name, creation time, last-use time, and actions.
- Rename changes only the site nickname. It does not require another password check.
- Delete opens a dedicated confirmation page with password and any required OTP fields.
- Explain that deletion stops future WCA sign-ins but leaves existing sessions and the provider's saved copy intact.
- For the last passkey, name the remaining password and OTP sign-in method.
- Keep cancellation reversible. Show a retry message rather than a success message after a dismissed browser prompt.
- Announce progress through a live region. Move focus to an error message when the request fails.
- Use clear text for unsupported browsers. Keep password sign-in available.

## Sign-in choices

The explicit **Sign in with a passkey** button supports discoverable credentials without entering an account name.
Password sign-in remains available beside it. These are deliberate choices for the current proof of concept.
Conditional autofill is a useful later enhancement, rather than a replacement for the explicit action.
It needs coordinated challenges and cancellation when users switch between password, explicit passkey, and autofill flows.
Do not add automatic creation or repeated promotion prompts in this change.

## Sources

- [FIDO: create, view, and manage passkeys](https://www.passkeycentral.org/design-user-journeys/required-patterns/create-view-and-manage-passkeys-in-account-settings)
- [FIDO: UX principles](https://www.passkeycentral.org/design-user-journeys/principles)
- [FIDO: manage different passkey types](https://www.passkeycentral.org/design-user-journeys/optional-patterns/passkey-management-ui-best-practices-for-combining-all-passkey-types)
- [FIDO: delete passkeys](https://www.passkeycentral.org/design-user-journeys/optional-patterns/remove-passkeys-from-service-provider-account-settings)
- [Google: passkey user journeys](https://developers.google.com/identity/passkeys/ux/user-journeys)
- [Google: interface design](https://developers.google.com/identity/passkeys/ux/user-interface-design)
- [GitHub: manage passkeys](https://docs.github.com/en/authentication/authenticating-with-a-passkey/managing-your-passkeys)
