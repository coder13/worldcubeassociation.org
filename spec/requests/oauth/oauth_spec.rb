# frozen_string_literal: true

require "rails_helper"

RSpec.describe "oauth api" do
  include Capybara::DSL

  # Pretend we're running on HTTPS, so that we can use the test server for redirect_uri.
  before :all do
    Capybara.default_host = Capybara.default_host.gsub("http", "https")
    default_url_options[:protocol] = "https"
  end

  after :all do
    Capybara.default_host = Capybara.default_host.gsub("https", "http")
    default_url_options[:protocol] = "http"
  end

  let(:user) { create(:user_with_wca_id) }

  it "redirect uri doesn't require ssl for localhost" do
    expect(build(:oauth_application, redirect_uri: "http://localhost:3000")).to be_valid
  end

  it 'can authenticate with grant_type password' do
    oauth_app = create(:oauth_application)

    post oauth_token_path, params: { grant_type: "password", client_id: oauth_app.uid, client_secret: oauth_app.secret, username: user.email, password: user.password, scope: "public email" }
    expect(response).to be_successful
    json = response.parsed_body
    expect(json['error']).to be_nil
    access_token = json['access_token']
    expect(access_token).not_to be_nil
    verify_access_token access_token
  end

  it 'rejects the cms scope for the password grant' do
    oauth_app = create(:oauth_application, scopes: "openid cms")

    post oauth_token_path, params: { grant_type: "password", client_id: oauth_app.uid, client_secret: oauth_app.secret, username: user.email, password: user.password, scope: "openid cms" }

    expect(response).to have_http_status(:bad_request)
    expect(response.parsed_body['error']).to eq('invalid_scope')
  end

  context "grant_type authorization" do
    let(:oauth_app) { create(:oauth_application, redirect_uri: oauth_authorization_url) }

    it 'can authenticate with grant_type authorization' do
      visit oauth_authorization_path(
        client_id: oauth_app.uid,
        redirect_uri: oauth_authorization_url,
        response_type: "code",
        scope: "public email",
      )

      # Pretend we're the user:
      #  1. Log in
      fill_in "user_login", with: user.email
      fill_in "user_password", with: user.password
      click_button "Sign in"
      #  2. Authorize the application
      click_button "Authorize"

      query = Rack::Utils.parse_query(URI.parse(current_url).query)
      authorization_code = query["code"]

      # We've now received an authorization_code from the user, lets request an
      # access_token.
      post oauth_token_path, params: { grant_type: "authorization_code", client_id: oauth_app.uid, client_secret: oauth_app.secret, code: authorization_code, redirect_uri: oauth_authorization_url }
      expect(response).to be_successful
      json = response.parsed_body
      expect(json['error']).to be_nil
      access_token = json['access_token']
      expect(access_token).not_to be_nil
      verify_access_token access_token
    end

    it "requires that redirect_uri matches" do
      visit oauth_authorization_path(
        client_id: oauth_app.uid,
        redirect_uri: "http://example.com/different-url",
        response_type: "code",
        scope: "public email",
      )

      # Pretend we're the user:
      #  1. Log in
      fill_in "user_login", with: user.email
      fill_in "user_password", with: user.password
      click_button "Sign in"
      #  2. Expect to see a complain about the redirect uri being incorrect
      expect(page).to have_text "The requested redirect URI is malformed or doesn't match the client redirect URI."
    end

    it 'can use refresh token' do
      visit oauth_authorization_path(
        client_id: oauth_app.uid,
        redirect_uri: oauth_authorization_url,
        response_type: "code",
        scope: "public email",
      )

      # Pretend we're the user:
      #  1. Log in
      fill_in "user_login", with: user.email
      fill_in "user_password", with: user.password
      click_button "Sign in"
      #  2. Authorize the application
      click_button "Authorize"

      query = Rack::Utils.parse_query(URI.parse(current_url).query)
      authorization_code = query["code"]

      # We've now received an authorization_code from the user, lets request an
      # access_token.
      post oauth_token_path, params: { grant_type: "authorization_code", client_id: oauth_app.uid, client_secret: oauth_app.secret, code: authorization_code, redirect_uri: oauth_authorization_url }
      expect(response).to be_successful
      json = response.parsed_body
      expect(json['error']).to be_nil
      access_token = json['access_token']
      expect(access_token).not_to be_nil
      verify_access_token access_token
      refresh_token = json['refresh_token']
      expect(refresh_token).not_to be_nil

      # Since we now have a refresh token, we should be able to get a new access
      # token.
      post oauth_token_path, params: { grant_type: "refresh_token", client_id: oauth_app.uid, client_secret: oauth_app.secret, redirect_uri: oauth_authorization_url, refresh_token: refresh_token }
      expect(response).to be_successful
      json = response.parsed_body
      expect(json['error']).to be_nil
      access_token = json['access_token']
      expect(access_token).not_to be_nil
      verify_access_token access_token
    end

    context "with dangerously_allow_any_redirect_uri set" do
      before(:each) do
        oauth_app.update!(dangerously_allow_any_redirect_uri: true)
      end

      it "allows any redirect_uri" do
        different_redirect_uri = "http://example.com/"
        visit oauth_authorization_path(
          client_id: oauth_app.uid,
          redirect_uri: different_redirect_uri,
          response_type: "code",
          scope: "public email",
        )

        # Pretend we're the user:
        #  1. Log in
        fill_in "user_login", with: user.email
        fill_in "user_password", with: user.password
        click_button "Sign in"
        #  2. Authorize the application
        click_button "Authorize"

        query = Rack::Utils.parse_query(URI.parse(current_url).query)
        authorization_code = query["code"]

        # We've now received an authorization_code from the user, lets request an
        # access_token.
        post oauth_token_path, params: { grant_type: "authorization_code", client_id: oauth_app.uid, client_secret: oauth_app.secret, code: authorization_code, redirect_uri: different_redirect_uri }
        expect(response).to be_successful
        json = response.parsed_body
        expect(json['error']).to be_nil
        access_token = json['access_token']
        expect(access_token).not_to be_nil
        verify_access_token access_token
      end
    end
  end

  context "with the cms scope" do
    let(:oauth_app) do
      create(
        :oauth_application,
        redirect_uri: oauth_authorization_url,
        scopes: "openid profile email cms",
        superapp: true,
      )
    end

    it "rejects a user without a CMS role" do
      visit_cms_authorization

      expect(page.status_code).to eq(403)
      expect(page).to have_text("invalid_scope")
    end

    it "rejects an untrusted OAuth application" do
      oauth_app.update!(superapp: false)
      create(:wst_member_role, user: user)

      visit_cms_authorization

      expect(page.status_code).to eq(403)
      expect(page).to have_text("invalid_scope")
    end

    it "allows a CMS user through a trusted OAuth application" do
      create(:wst_member_role, user: user)

      visit_cms_authorization

      query = Rack::Utils.parse_query(URI.parse(current_url).query)
      expect(query["code"]).to be_present
    end

    def visit_cms_authorization
      visit oauth_authorization_path(
        client_id: oauth_app.uid,
        redirect_uri: oauth_authorization_url,
        response_type: "code",
        scope: "openid profile email cms",
      )

      fill_in "user_login", with: user.email
      fill_in "user_password", with: user.password
      click_button "Sign in"
    end
  end

  it 'can authenticate with response_type token (implicit authorization)' do
    oauth_app = create(:oauth_application)
    visit oauth_authorization_path(
      client_id: oauth_app.uid,
      redirect_uri: oauth_app.redirect_uri,
      response_type: "token",
      scope: "public email",
    )

    # Pretend we're the user:
    #  1. Log in
    fill_in "user_login", with: user.email
    fill_in "user_password", with: user.password
    click_button "Sign in"
    #  2. Authorize the application
    click_button "Authorize"

    query = Rack::Utils.parse_query(URI.parse(current_url).query)
    access_token = query["access_token"]
    expect(access_token).not_to be_nil
    verify_access_token access_token
  end

  def verify_access_token(access_token)
    integration_session.reset! # posting to oauth_token_path littered our state
    get api_v0_me_path, headers: { "Authorization" => "Bearer #{access_token}" }
    expect(response).to be_successful
    json = response.parsed_body
    # We just do a sanity check of the /me route here. There is a more
    # complete test in api_controller_spec.
    expect(json['me']['id']).to eq(user.id)
    expect(json['me']['dob']).to be_nil
    expect(json['me']['email']).to eq(user.email)
  end
end
