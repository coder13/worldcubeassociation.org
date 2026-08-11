# frozen_string_literal: true

class Oauth::AuthorizationsController < Doorkeeper::AuthorizationsController
  before_action :authorize_cms_scope

  private def authorize_cms_scope
    return unless requested_scopes.exists?("cms")

    application = Doorkeeper::Application.by_uid(params[:client_id])
    return if application&.superapp? && current_resource_owner&.can_use_cms?

    render json: {
      error: "invalid_scope",
      error_description: "This application or user cannot request the cms scope.",
    }, status: :forbidden
  end

  private def requested_scopes
    Doorkeeper::OAuth::Scopes.from_string(params[:scope])
  end
end
