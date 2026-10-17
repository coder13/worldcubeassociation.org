# frozen_string_literal: true

require 'rails_helper'
require 'webauthn/fake_client'

RSpec.describe 'Passkeys' do
  let(:account) { create(:user) }
  let(:authenticator) { WebAuthn::FakeAuthenticator.new }
  let(:client) { WebAuthn::FakeClient.new(EnvConfig.ROOT_URL, authenticator: authenticator) }

  before { allow(EnvConfig).to receive(:PASSKEYS_ENABLED?).and_return(true) }

  def registration_payload(password: 'wca', otp_attempt: nil, user_verified: true, user_present: true)
    sign_in account
    post registration_options_passkeys_path, params: { password: password, otp_attempt: otp_attempt }, as: :json
    client.create(challenge: response.parsed_body.fetch('challenge'), user_verified: user_verified, user_present: user_present)
  end

  def enroll_passkey
    payload = registration_payload
    post passkeys_path, params: { name: 'My laptop', credential: payload }, as: :json
    expect(response).to have_http_status(:ok)
    account.passkeys.sole
  end

  def assertion_payload(**attributes)
    post authentication_options_passkeys_path, as: :json
    client.get(
      challenge: response.parsed_body.fetch('challenge'),
      user_handle: WebAuthn.configuration.encoder.decode(account.reload.passkey_user_handle),
      user_verified: true,
      **attributes,
    )
  end

  describe 'feature flag' do
    before { allow(EnvConfig).to receive(:PASSKEYS_ENABLED?).and_return(false) }

    it 'disables all passkey endpoints' do
      get passkeys_path
      expect(response).to have_http_status(:not_found)
      get new_passkey_path
      expect(response).to have_http_status(:not_found)
      get edit_passkey_path(1)
      expect(response).to have_http_status(:not_found)
      get confirm_destroy_passkey_path(1)
      expect(response).to have_http_status(:not_found)
      patch passkey_path(1), params: { passkey: { name: 'Renamed' } }
      expect(response).to have_http_status(:not_found)
      post registration_options_passkeys_path, as: :json
      expect(response).to have_http_status(:not_found)
      post passkeys_path, as: :json
      expect(response).to have_http_status(:not_found)
      post authentication_options_passkeys_path, as: :json
      expect(response).to have_http_status(:not_found)
      post authenticate_passkeys_path, as: :json
      expect(response).to have_http_status(:not_found)
      delete passkey_path(1)
      expect(response).to have_http_status(:not_found)
    end

    it 'hides the sign-in control' do
      get new_user_session_path
      expect(response.body).not_to include('data-passkey-form')
    end
  end

  describe 'management pages' do
    before { sign_in account }

    it 'shows a creation link without password or nickname fields on the list' do
      get passkeys_path
      expect(response.parsed_body.at_css("a[href='#{new_passkey_path}']")).to be_present
      expect(response.parsed_body.css('input[type="password"], input[name="name"]')).to be_empty
    end

    it 'asks for identity confirmation before creation without asking for a nickname' do
      get new_passkey_path
      expect(response.parsed_body.at_css('input[name="password"]')).to be_present
      expect(response.parsed_body.at_css('input[name="name"]')).to be_nil
      expect(response.parsed_body.at_css('input[name="otp_attempt"]')).to be_nil
      expect(response.body).to include(CGI.escapeHTML(account.email))
    end

    it 'shows the two-factor field when the account requires it' do
      account.update!(otp_required_for_login: true, otp_secret: User.generate_otp_secret)
      get new_passkey_path
      expect(response.parsed_body.at_css('input[name="otp_attempt"]')).to be_present
    end
  end

  describe 'registration' do
    it 'creates a passkey without a nickname and redirects to optional naming' do
      payload = registration_payload
      post passkeys_path, params: { credential: payload }, as: :json
      passkey = account.passkeys.sole
      expect(passkey.name).to eq 'Passkey 1'
      expect(response.parsed_body.fetch('redirect_url')).to eq edit_passkey_path(passkey)
      get edit_passkey_path(passkey)
      expect(response.body).to include(I18n.t('passkeys.created_success'))
      expect(response.parsed_body.at_css('input[name="passkey[name]"]')['required']).to be_nil
    end

    it 'uses a distinct suggested name when another passkey already has the first name' do
      passkey = enroll_passkey
      passkey.update!(name: 'Passkey 1')
      payload = registration_payload
      post passkeys_path, params: { credential: payload }, as: :json
      expect(account.passkeys.order(:id).last.name).to eq 'Passkey 2'
    end

    it 'requires a signed-in account' do
      post registration_options_passkeys_path, params: { password: 'wca' }, as: :json
      expect(response).to have_http_status(:unauthorized)
      expect(PasskeyChallenge.count).to eq 0
    end

    it 'requires the current password, even in an authenticated session' do
      sign_in account
      post registration_options_passkeys_path, params: { password: 'incorrect password' }, as: :json
      expect(response).to have_http_status(:unprocessable_content)
      expect(PasskeyChallenge.count).to eq 0
    end

    it 'requires the existing second factor as well as the password' do
      account.update!(otp_required_for_login: true, otp_secret: User.generate_otp_secret)
      sign_in account
      post registration_options_passkeys_path, params: { password: 'wca' }, as: :json
      expect(response).to have_http_status(:unprocessable_content)
      post registration_options_passkeys_path, params: { password: 'wca', otp_attempt: 'invalid code' }, as: :json
      expect(response).to have_http_status(:unprocessable_content)
      post registration_options_passkeys_path, params: { password: 'wca', otp_attempt: account.current_otp }, as: :json
      expect(response).to have_http_status(:ok)
    end

    it 'requests discoverable credentials and mandatory device verification' do
      registration_payload
      options = response.parsed_body
      expect(options.fetch('authenticatorSelection')).to include('residentKey' => 'required', 'userVerification' => 'required')
      expect(options.fetch('user').fetch('id')).to eq account.reload.passkey_user_handle
      expect(response.headers['Cache-Control']).to eq 'no-store'
    end

    it 'stores a verified public key and excludes it from subsequent registration' do
      passkey = enroll_passkey
      expect(passkey.name).to eq 'My laptop'
      expect(passkey.public_key).to be_present
      expect(passkey.sign_count).to eq 0
      expect(PasskeyChallenge.count).to eq 0
      post registration_options_passkeys_path, params: { password: 'wca' }, as: :json
      expect(response.parsed_body.fetch('excludeCredentials')).to include('type' => 'public-key', 'id' => passkey.credential_id)
    end

    it 'rejects missing device verification' do
      payload = registration_payload(user_verified: false)
      expect { post passkeys_path, params: { name: 'Unverified', credential: payload }, as: :json }.not_to change(Passkey, :count)
      expect(response).to have_http_status(:unprocessable_content)
    end

    it 'rejects missing user presence during registration' do
      payload = registration_payload(user_present: false)
      post passkeys_path, params: { name: 'No presence', credential: payload }, as: :json
      expect(response).to have_http_status(:unprocessable_content)
      expect(Passkey.count).to eq 0
    end

    it 'rejects an expired challenge' do
      payload = registration_payload
      Timecop.travel(6.minutes.from_now) do
        post passkeys_path, params: { name: 'Expired', credential: payload }, as: :json
        expect(response).to have_http_status(:unprocessable_content)
      end
      expect(Passkey.count).to eq 0
    end

    it 'rejects an account change between challenge creation and registration' do
      payload = registration_payload
      sign_out account
      sign_in create(:user)
      post passkeys_path, params: { name: 'Wrong owner', credential: payload }, as: :json
      expect(response).to have_http_status(:unprocessable_content)
      expect(Passkey.count).to eq 0
    end

    it 'rejects an ID that differs from the attested credential' do
      enroll_passkey
      post registration_options_passkeys_path, params: { password: 'wca' }, as: :json
      payload = client.create(challenge: response.parsed_body.fetch('challenge'), user_verified: true)
      # FakeClient creates a new key each time. Submit the stored ID to exercise
      # the verifier's binding between the outer ID and attested credential.
      payload['id'] = account.passkeys.sole.credential_id
      payload['rawId'] = payload['id']
      post passkeys_path, params: { name: 'Duplicate', credential: payload }, as: :json
      expect(response).to have_http_status(:unprocessable_content)
      expect(Passkey.count).to eq 1
    end
  end

  describe 'password fallback' do
    it 'still accepts the account password' do
      post user_session_path, params: { user: { login: account.email, password: 'wca' } }
      get passkeys_path
      expect(response).to have_http_status(:ok)
    end

    it 'still requires an enabled OTP after the password' do
      account.update!(otp_required_for_login: true, otp_secret: User.generate_otp_secret)
      post user_session_path, params: { user: { login: account.email, password: 'wca' } }
      expect(response.body).to include('user_otp_attempt')
      get passkeys_path
      expect(response).to redirect_to(new_user_session_path)
      post user_session_path, params: { user: { otp_attempt: account.current_otp } }
      get passkeys_path
      expect(response).to have_http_status(:ok)
    end
  end

  describe 'sign-in' do
    let!(:passkey) { enroll_passkey }

    before { sign_out account }

    it 'signs in without an account name and retains the stored destination' do
      get edit_user_path(account)
      payload = assertion_payload
      expect(response.parsed_body['allowCredentials']).to be_blank
      post authenticate_passkeys_path, params: { credential: payload }, as: :json
      expect(response).to have_http_status(:ok)
      expect(response.parsed_body.fetch('redirect_url')).to end_with(edit_user_path(account))
      expect(passkey.reload.last_used_at).to be_present
      expect(passkey.sign_count).to be_positive
      get passkeys_path
      expect(response).to have_http_status(:ok)
      expect(response.body).to include('My laptop')
    end

    it 'accepts a verified passkey for an account with OTP enabled' do
      account.update!(otp_required_for_login: true, otp_secret: User.generate_otp_secret)
      payload = assertion_payload
      post authenticate_passkeys_path, params: { credential: payload }, as: :json
      expect(response).to have_http_status(:ok)
      get passkeys_path
      expect(response).to have_http_status(:ok)
    end

    it 'rejects missing user verification, including for accounts with OTP enabled' do
      account.update!(otp_required_for_login: true, otp_secret: User.generate_otp_secret)
      payload = assertion_payload(user_verified: false)
      post authenticate_passkeys_path, params: { credential: payload }, as: :json
      expect(response).to have_http_status(:unprocessable_content)
      expect(passkey.reload.last_used_at).to be_nil
      get passkeys_path
      expect(response).to redirect_to(new_user_session_path)
    end

    it 'rejects an invalid signature' do
      payload = assertion_payload
      payload['response']['signature'] = WebAuthn.configuration.encoder.encode('invalid signature')
      post authenticate_passkeys_path, params: { credential: payload }, as: :json
      expect(response).to have_http_status(:unprocessable_content)
      expect(passkey.reload.last_used_at).to be_nil
    end

    it 'rejects missing user presence' do
      payload = assertion_payload(user_present: false)
      post authenticate_passkeys_path, params: { credential: payload }, as: :json
      expect(response).to have_http_status(:unprocessable_content)
    end

    it 'rejects another origin' do
      post authentication_options_passkeys_path, as: :json
      foreign_client = WebAuthn::FakeClient.new('https://example.org', authenticator: authenticator)
      payload = foreign_client.get(
        challenge: response.parsed_body.fetch('challenge'),
        rp_id: URI.parse(EnvConfig.ROOT_URL).host,
        user_verified: true,
        user_handle: WebAuthn.configuration.encoder.decode(account.reload.passkey_user_handle),
      )
      post authenticate_passkeys_path, params: { credential: payload }, as: :json
      expect(response).to have_http_status(:unprocessable_content)
    end

    it 'rejects a valid signature from a cross-origin iframe' do
      post authentication_options_passkeys_path, as: :json
      encoder = WebAuthn.configuration.encoder
      client_data = { type: 'webauthn.get', challenge: response.parsed_body.fetch('challenge'), origin: EnvConfig.ROOT_URL, crossOrigin: true }.to_json
      assertion = authenticator.get_assertion(
        rp_id: URI.parse(EnvConfig.ROOT_URL).host,
        client_data_hash: OpenSSL::Digest::SHA256.digest(client_data),
        user_verified: true,
      )
      payload = {
        type: 'public-key', id: passkey.credential_id, rawId: passkey.credential_id,
        response: {
          clientDataJSON: encoder.encode(client_data),
          authenticatorData: encoder.encode(assertion.fetch(:authenticator_data)),
          signature: encoder.encode(assertion.fetch(:signature)),
          userHandle: account.reload.passkey_user_handle,
        }
      }
      post authenticate_passkeys_path, params: { credential: payload }, as: :json
      expect(response).to have_http_status(:unprocessable_content)
    end

    it 'rejects an expired sign-in challenge' do
      payload = assertion_payload
      Timecop.travel(6.minutes.from_now) do
        post authenticate_passkeys_path, params: { credential: payload }, as: :json
        expect(response).to have_http_status(:unprocessable_content)
      end
    end

    it 'rejects a stale nonzero signature counter' do
      payload = assertion_payload(sign_count: 10)
      post authenticate_passkeys_path, params: { credential: payload }, as: :json
      expect(response).to have_http_status(:ok)
      sign_out account
      payload = assertion_payload(sign_count: 10)
      post authenticate_passkeys_path, params: { credential: payload }, as: :json
      expect(response).to have_http_status(:unprocessable_content)
      expect(passkey.reload.sign_count).to eq 10
    end

    it 'rejects a different user handle' do
      payload = assertion_payload(user_handle: 'another account')
      post authenticate_passkeys_path, params: { credential: payload }, as: :json
      expect(response).to have_http_status(:unprocessable_content)
    end

    it 'rejects an unconfirmed account' do
      account.update!(confirmed_at: nil)
      payload = assertion_payload
      post authenticate_passkeys_path, params: { credential: payload }, as: :json
      expect(response).to have_http_status(:unprocessable_content)
    end

    it 'rejects a missing challenge' do
      payload = assertion_payload
      PasskeyChallenge.delete_all
      post authenticate_passkeys_path, params: { credential: payload }, as: :json
      expect(response).to have_http_status(:unprocessable_content)
    end

    it 'rejects an assertion from a different browser session' do
      payload = assertion_payload
      other_browser = ActionDispatch::Integration::Session.new(Rails.application)
      other_browser.post authenticate_passkeys_path, params: { credential: payload }, as: :json
      expect(other_browser.response).to have_http_status(:unprocessable_content)
    end

    it 'rejects replay even with the old cookie and a zero signature counter' do
      payload = assertion_payload(sign_count: 0)
      challenge_cookie = cookies['_WcaOnRails_session'].dup
      post authenticate_passkeys_path, params: { credential: payload }, as: :json
      expect(response).to have_http_status(:ok)
      sign_out account
      cookies['_WcaOnRails_session'] = challenge_cookie
      post authenticate_passkeys_path, params: { credential: payload }, as: :json
      expect(response).to have_http_status(:unprocessable_content)
    end

    it 'consumes a failed attempt before a retry' do
      payload = assertion_payload
      invalid_payload = payload.deep_dup
      invalid_payload['response']['userHandle'] = WebAuthn.configuration.encoder.encode('another account')
      post authenticate_passkeys_path, params: { credential: invalid_payload }, as: :json
      expect(response).to have_http_status(:unprocessable_content)
      post authenticate_passkeys_path, params: { credential: payload }, as: :json
      expect(response).to have_http_status(:unprocessable_content)
    end

    it 'rejects malformed payloads without signing in' do
      post authentication_options_passkeys_path, as: :json
      post authenticate_passkeys_path, params: { credential: { type: 'public-key', id: [], rawId: {}, response: {} } }, as: :json
      expect(response).to have_http_status(:unprocessable_content)
      expect(passkey.reload.last_used_at).to be_nil
    end
  end

  describe 'deletion' do
    let!(:passkey) { enroll_passkey }

    it 'requires the current password' do
      delete passkey_path(passkey), params: { password: 'incorrect password' }
      expect(Passkey.exists?(passkey.id)).to be true
      expect(response).to have_http_status(:unprocessable_content)
      expect(response.body).to include(I18n.t('passkeys.identity_error'), CGI.escapeHTML(passkey.name))
    end

    it 'shows a last-passkey warning and confirmation without deleting on GET' do
      get confirm_destroy_passkey_path(passkey)
      expect(response.body).to include(I18n.t('passkeys.delete_last'), I18n.t('passkeys.delete_saved_copy'))
      expect(response.parsed_body.at_css('input[name="password"]')).to be_present
      expect(Passkey.exists?(passkey.id)).to be true
    end

    it 'includes two-factor fallback and confirmation for an account with OTP' do
      account.update!(otp_required_for_login: true, otp_secret: User.generate_otp_secret)
      get confirm_destroy_passkey_path(passkey)
      expect(response.body).to include(I18n.t('passkeys.delete_last_with_otp'))
      expect(response.parsed_body.at_css('input[name="otp_attempt"]')).to be_present
    end

    it 'requires an enabled second factor' do
      account.update!(otp_required_for_login: true, otp_secret: User.generate_otp_secret)
      delete passkey_path(passkey), params: { password: 'wca' }
      expect(Passkey.exists?(passkey.id)).to be true
      delete passkey_path(passkey), params: { password: 'wca', otp_attempt: account.current_otp }
      expect(Passkey.exists?(passkey.id)).to be false
    end

    it 'deletes an owned credential' do
      expect { delete passkey_path(passkey), params: { password: 'wca' } }.to change(Passkey, :count).by(-1)
      expect(response).to redirect_to(passkeys_path)
    end

    it 'does not let another account delete the credential' do
      sign_out account
      sign_in create(:user)
      expect { delete passkey_path(passkey), params: { password: 'wca' } }.to raise_error(ActiveRecord::RecordNotFound)
      expect(Passkey.exists?(passkey.id)).to be true
    end
  end

  describe 'renaming' do
    let!(:passkey) { enroll_passkey }

    it 'changes only the nickname without requesting the account password' do
      original_key = passkey.public_key
      patch passkey_path(passkey), params: { passkey: { name: 'Personal password manager', public_key: 'replacement' } }
      expect(response).to redirect_to(passkeys_path)
      expect(passkey.reload.name).to eq 'Personal password manager'
      expect(passkey.public_key).to eq original_key
    end

    it 'keeps the suggested name when the optional input is blank' do
      patch passkey_path(passkey), params: { passkey: { name: '  ' } }
      expect(passkey.reload.name).to eq 'My laptop'
    end

    it 'shows an error without saving an oversized name' do
      patch passkey_path(passkey), params: { passkey: { name: 'x' * (Passkey::NAME_MAX_LENGTH + 1) } }
      expect(response).to have_http_status(:unprocessable_content)
      expect(passkey.reload.name).to eq 'My laptop'
    end

    it 'requires a signed-in account' do
      sign_out account
      patch passkey_path(passkey), params: { passkey: { name: 'Not allowed' } }
      expect(response).to redirect_to(new_user_session_path)
    end

    context 'with another account' do
      before do
        sign_out account
        sign_in create(:user)
      end

      it 'does not expose the rename form' do
        expect { get edit_passkey_path(passkey) }.to raise_error(ActiveRecord::RecordNotFound)
      end

      it 'does not expose the delete confirmation' do
        expect { get confirm_destroy_passkey_path(passkey) }.to raise_error(ActiveRecord::RecordNotFound)
      end

      it 'does not change the name' do
        expect { patch passkey_path(passkey), params: { passkey: { name: 'Not allowed' } } }.to raise_error(ActiveRecord::RecordNotFound)
      end
    end
  end

  describe 'CSRF protection' do
    around do |example|
      previous_value = ActionController::Base.allow_forgery_protection
      ActionController::Base.allow_forgery_protection = true
      example.run
    ensure
      ActionController::Base.allow_forgery_protection = previous_value
    end

    it 'rejects tokenless authentication requests' do
      expect { post authentication_options_passkeys_path, as: :json }.to raise_error(ActionController::InvalidAuthenticityToken)
    end

    it 'accepts the page CSRF token at both endpoints of each ceremony' do
      sign_in account
      get passkeys_path
      token = response.parsed_body.at_css('meta[name="csrf-token"]')['content']
      headers = { 'X-CSRF-Token' => token }
      post registration_options_passkeys_path, params: { password: 'wca' }, headers: headers, as: :json
      expect(response).to have_http_status(:ok)
      payload = client.create(challenge: response.parsed_body.fetch('challenge'), user_verified: true)
      post passkeys_path, params: { name: 'My laptop', credential: payload }, headers: headers, as: :json
      expect(response).to have_http_status(:ok)

      sign_out account
      get new_user_session_path
      token = response.parsed_body.at_css('meta[name="csrf-token"]')['content']
      headers = { 'X-CSRF-Token' => token }
      post authentication_options_passkeys_path, headers: headers, as: :json
      expect(response).to have_http_status(:ok)
      payload = client.get(
        challenge: response.parsed_body.fetch('challenge'),
        user_handle: WebAuthn.configuration.encoder.decode(account.reload.passkey_user_handle),
        user_verified: true,
      )
      post authenticate_passkeys_path, params: { credential: payload }, headers: headers, as: :json
      expect(response).to have_http_status(:ok)
    end
  end
end
