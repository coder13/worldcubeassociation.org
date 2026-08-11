# frozen_string_literal: true

module ApiSignInHelper
  DEFAULT_API_SCOPES = %w[
    read_registrations
    manage_registrations
    manage_live_results
  ].freeze

  def api_sign_in_as(user, scopes: nil)
    unless scopes
      scopes = Doorkeeper::OAuth::Scopes.new
      scopes.add(*DEFAULT_API_SCOPES)
    end
    token = double acceptable?: true, accessible?: true, resource_owner_id: user.id, scopes: scopes
    allow_any_instance_of(ApplicationController).to receive(:doorkeeper_token).and_return(token)
  end
end
