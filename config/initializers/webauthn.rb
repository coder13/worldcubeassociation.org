# frozen_string_literal: true

WebAuthn.configure do |config|
  # Use a trusted deployment URL, never the request Host header. A separate host
  # for staging keeps its credentials separate from production credentials.
  origin = URI.parse(EnvConfig.ROOT_URL)
  config.allowed_origins = ["#{origin.scheme}://#{origin.host}#{":#{origin.port}" unless origin.port == origin.default_port}"]
  config.rp_id = origin.host
  config.rp_name = 'World Cube Association'
end
