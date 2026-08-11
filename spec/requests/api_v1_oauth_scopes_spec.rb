# frozen_string_literal: true

require "rails_helper"

RSpec.describe "API v1 OAuth scopes" do
  def oauth_scopes(*values)
    Doorkeeper::OAuth::Scopes.new.tap { |scopes| scopes.add(*values) }
  end

  let(:public_scopes) { oauth_scopes("public") }

  describe "registration scopes" do
    let(:user) { create(:user) }
    let(:competition) { create(:competition, :registration_open) }

    it "rejects private registration reads with only the public scope" do
      registration = create(:registration, competition: competition, user: user)
      api_sign_in_as(user, scopes: public_scopes)

      get api_v1_registration_path(registration)

      expect(response).to have_http_status(:forbidden)
      expect(response.parsed_body["error"]).to eq("Missing required OAuth scope 'read_registrations'")
    end

    it "rejects registration changes with only the public scope" do
      registration_request = build(:registration_request, competition_id: competition.id, user_id: user.id)
      api_sign_in_as(user, scopes: public_scopes)

      post api_v1_competition_registrations_path(competition), params: registration_request

      expect(response).to have_http_status(:forbidden)
      expect(response.parsed_body["error"]).to eq("Missing required OAuth scope 'manage_registrations'")
    end

    it "allows registration changes with the manage_registrations scope" do
      registration_request = build(:registration_request, competition_id: competition.id, user_id: user.id)
      api_sign_in_as(user, scopes: oauth_scopes("manage_registrations"))

      post api_v1_competition_registrations_path(competition), params: registration_request

      expect(response).to have_http_status(:accepted)
    end

    it "does not require an OAuth scope for a cookie session" do
      registration_request = build(:registration_request, competition_id: competition.id, user_id: user.id)
      sign_in user

      post api_v1_competition_registrations_path(competition), params: registration_request

      expect(response).to have_http_status(:accepted)
    end
  end

  describe "live result scopes" do
    let(:delegate) { create(:delegate) }
    let(:competition) do
      create(
        :competition,
        scoretaking_software: :internal,
        event_ids: ["333"],
        delegates: [delegate],
      )
    end
    let(:round) { create(:round, competition: competition, event_id: "333") }
    let(:registration) { create(:registration, :accepted, competition: competition) }
    let(:live_request) do
      {
        attempts: [{ value: 111, attempt_number: 1 }],
        registration_id: registration.id,
      }
    end

    before do
      registration
      round.open_round!(delegate)
    end

    it "rejects live result changes with only the public scope" do
      api_sign_in_as(delegate, scopes: public_scopes)

      post api_v1_competition_live_add_results_path(competition.id, round.wcif_id), params: live_request

      expect(response).to have_http_status(:forbidden)
      expect(response.parsed_body["error"]).to eq("Missing required OAuth scope 'manage_live_results'")
    end

    it "allows live result changes with the manage_live_results scope" do
      api_sign_in_as(delegate, scopes: oauth_scopes("manage_live_results"))

      post api_v1_competition_live_add_results_path(competition.id, round.wcif_id), params: live_request

      expect(response).to be_successful
    end
  end

  describe "competition administration scope" do
    let(:delegate) { create(:delegate) }
    let(:competition) do
      create(
        :competition,
        scoretaking_software: :internal,
        event_ids: ["333"],
        delegates: [delegate],
      )
    end
    let(:scoretaker) { create(:user) }

    it "rejects scoretaker changes with only the public scope" do
      api_sign_in_as(delegate, scopes: public_scopes)

      post api_v1_competition_scoretakers_path(competition.id), params: { user_id: scoretaker.id }

      expect(response).to have_http_status(:forbidden)
      expect(response.parsed_body["error"]).to eq("Missing required OAuth scope 'manage_competitions'")
      expect(competition.reload.scoretakers).to be_empty
    end

    it "allows scoretaker changes with the manage_competitions scope" do
      api_sign_in_as(delegate, scopes: oauth_scopes("manage_competitions"))

      post api_v1_competition_scoretakers_path(competition.id), params: { user_id: scoretaker.id }

      expect(response).to be_successful
      expect(competition.reload.scoretakers).to include(scoretaker)
    end
  end
end
