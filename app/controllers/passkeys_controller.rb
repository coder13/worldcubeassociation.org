# frozen_string_literal: true

class PasskeysController < ApplicationController
  class InvalidCeremony < StandardError; end
  class InvalidIdentity < InvalidCeremony; end
  MAX_BINARY_FIELD_BYTES = 128.kilobytes

  before_action :require_passkeys_enabled
  before_action :disable_caching
  before_action :authenticate_user!, except: %i[authentication_options authenticate]
  before_action :require_signed_out, only: %i[authentication_options authenticate]
  before_action :set_passkey, only: %i[edit update confirm_destroy destroy]
  before_action :authenticate_account_owner, only: %i[registration_options destroy]

  protect_from_forgery with: :exception, prepend: true
  rate_limit to: 10, within: 1.minute, only: %i[registration_options create update destroy authentication_options authenticate] if Rails.env.production?

  rescue_from InvalidCeremony, WebAuthn::Error, JSON::ParserError, ArgumentError, OpenSSL::OpenSSLError,
              CBOR::UnpackError, CBOR::TypeError, ActiveRecord::RecordInvalid, ActiveRecord::RecordNotUnique,
              with: :invalid_ceremony
  rescue_from InvalidIdentity, with: :invalid_identity

  def index
    @passkeys = current_user.passkeys.order(:created_at)
  end

  def new
  end

  def edit
  end

  def confirm_destroy
  end

  def registration_options
    current_user.with_lock do
      current_user.update!(passkey_user_handle: WebAuthn.generate_user_id) unless current_user.passkey_user_handle?
    end

    options = WebAuthn::Credential.options_for_create(
      user: { id: current_user.passkey_user_handle, name: current_user.email, display_name: current_user.name },
      exclude: current_user.passkeys.pluck(:credential_id),
      authenticator_selection: { resident_key: 'required', user_verification: 'required' },
      attestation: 'none',
    )
    issue_challenge!(options.challenge, 'registration', user: current_user)
    render json: options
  end

  def create
    challenge = consume_challenge!('registration', user: current_user)
    credential = WebAuthn::Credential.from_create(credential_params)
    verify_credential!(credential, challenge.challenge)
    raise InvalidCeremony unless credential.raw_id == credential.response.authenticator_data.attested_credential_data.id

    name = params[:name]
    raise InvalidCeremony unless name.nil? || name.is_a?(String)

    passkey = current_user.with_lock do
      current_user.passkeys.create!(
        credential_id: credential.id,
        public_key: credential.public_key,
        sign_count: credential.sign_count,
        name: name&.strip.presence || next_passkey_name,
      )
    end
    flash[:notice] = t('passkeys.created_success')
    render json: { redirect_url: edit_passkey_path(passkey) }
  end

  def update
    name = params.expect(passkey: [:name])[:name]
    @passkey.name = name.strip if name.is_a?(String) && name.strip.present?
    if @passkey.save
      redirect_to passkeys_path, notice: t('passkeys.renamed'), status: :see_other
    else
      render :edit, status: :unprocessable_content
    end
  end

  def destroy
    @passkey.destroy!
    redirect_to passkeys_path, notice: t('passkeys.deleted'), status: :see_other
  end

  def authentication_options
    # An empty allow list lets the authenticator choose a discoverable passkey.
    # No account lookup or credential list reaches an unauthenticated client.
    options = WebAuthn::Credential.options_for_get(user_verification: 'required')
    issue_challenge!(options.challenge, 'authentication')
    render json: options
  end

  def authenticate
    challenge = consume_challenge!('authentication')
    credential = WebAuthn::Credential.from_get(credential_params)
    passkey = Passkey.find_by(credential_id: credential.id)
    raise InvalidCeremony unless passkey

    passkey.with_lock do
      raise InvalidCeremony unless credential.user_handle == passkey.user.passkey_user_handle && passkey.user.active_for_authentication?

      verify_credential!(credential, challenge.challenge, public_key: passkey.public_key, sign_count: passkey.sign_count)
      passkey.update!(sign_count: credential.sign_count, last_used_at: Time.current)
    end

    # A verified passkey includes possession and a device PIN or biometric check.
    # Keep the existing password + OTP route available as an independent fallback.
    return_path = stored_location_for(:user)
    reset_session
    sign_in(:user, passkey.user, event: :authentication)
    session[:last_authenticated_at] = Time.current
    store_location_for(:user, return_path) if return_path
    render json: { redirect_url: after_sign_in_path_for(passkey.user) }
  end

  private

    def set_passkey
      @passkey = current_user.passkeys.find(params.expect(:id))
    end

    def next_passkey_name
      names = current_user.passkeys.pluck(:name)
      number = 1
      number += 1 while names.include?(t('passkeys.default_name', number: number))
      t('passkeys.default_name', number: number)
    end

    def verify_credential!(credential, challenge, **attributes)
      credential.verify(challenge, user_presence: true, user_verification: true, **attributes)
      # webauthn 3.4 also accepts UV as presence. These interactive ceremonies
      # require the actual presence flag as well as device verification.
      raise InvalidCeremony unless credential.response.authenticator_data.user_present?
    end

    def require_passkeys_enabled
      head :not_found unless EnvConfig.PASSKEYS_ENABLED?
    end

    def disable_caching
      response.headers['Cache-Control'] = 'no-store'
    end

    def require_signed_out
      head :conflict if user_signed_in?
    end

    def authenticate_account_owner
      password = params[:password]
      raise InvalidIdentity unless password.is_a?(String) && current_user.valid_password?(password)
      return unless current_user.two_factor_enabled?

      otp = params[:otp_attempt]
      raise InvalidIdentity unless otp.is_a?(String) && (current_user.validate_and_consume_otp!(otp) || current_user.invalidate_otp_backup_code!(otp))
    end

    def issue_challenge!(challenge, ceremony, user: nil)
      PasskeyChallenge.where(id: session.delete(:passkey_challenge_id)).delete_all
      PasskeyChallenge.where(expires_at: ...Time.current).delete_all
      record = PasskeyChallenge.create!(challenge: challenge, ceremony: ceremony, user: user, expires_at: PasskeyChallenge::LIFETIME.from_now)
      session[:passkey_challenge_id] = record.id
    end

    def consume_challenge!(ceremony, user: nil)
      PasskeyChallenge.consume!(session.delete(:passkey_challenge_id), ceremony: ceremony, user: user) || raise(InvalidCeremony)
    end

    def credential_params
      credential = params.expect(credential: [:id, :rawId, :type, { response: [:clientDataJSON, :attestationObject, :authenticatorData, :signature, :userHandle, { transports: [] }] }]).to_h
      response = credential['response']
      raise InvalidCeremony unless credential['type'] == 'public-key' && response.is_a?(Hash)
      raise InvalidCeremony unless credential['id'].is_a?(String) && credential['id'].match?(Passkey::CREDENTIAL_ID_FORMAT) && credential['rawId'] == credential['id']

      required_fields = action_name == 'create' ? %w[clientDataJSON attestationObject] : %w[clientDataJSON authenticatorData signature userHandle]
      raise InvalidCeremony unless required_fields.all? { |field| response[field].is_a?(String) && response[field].match?(/\A[A-Za-z0-9_-]+\z/) && response[field].bytesize <= MAX_BINARY_FIELD_BYTES }

      # webauthn 3.4 does not reject cross-origin iframe ceremonies itself.
      client_data = JSON.parse(WebAuthn.configuration.encoder.decode(response['clientDataJSON']))
      raise InvalidCeremony unless client_data.is_a?(Hash) && client_data.fetch('crossOrigin', false) == false

      if action_name == 'create'
        attestation = CBOR.decode(WebAuthn.configuration.encoder.decode(response['attestationObject']))
        raise InvalidCeremony unless attestation.is_a?(Hash) && attestation['authData'].is_a?(String) && attestation['fmt'].is_a?(String) && attestation['attStmt'].is_a?(Hash)
      end

      credential
    end

    def invalid_ceremony
      if request.format.json?
        render json: { error: { message: t('passkeys.error') } }, status: :unprocessable_content
      else
        redirect_to passkeys_path, alert: t('passkeys.error'), status: :see_other
      end
    end

    def invalid_identity
      if action_name == 'destroy' && !request.format.json?
        @identity_error = t('passkeys.identity_error')
        render :confirm_destroy, status: :unprocessable_content
      else
        render json: { error: { message: t('passkeys.identity_error') } }, status: :unprocessable_content
      end
    end
end
