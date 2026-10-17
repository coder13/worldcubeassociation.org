# frozen_string_literal: true

class PasskeyChallenge < ApplicationRecord
  LIFETIME = 5.minutes.freeze

  belongs_to :user, optional: true

  validates :challenge, :expires_at, presence: true
  validates :ceremony, inclusion: { in: %w[registration authentication] }

  def self.consume!(id, ceremony:, user: nil)
    challenge = find_by(id: id)
    return unless challenge

    # CookieStore cannot revoke an older copy of a session cookie. The atomic
    # database delete permits only one attempt, including concurrent requests.
    return unless where(id: challenge.id).delete_all == 1
    return unless challenge.ceremony == ceremony && challenge.user_id == user&.id && challenge.expires_at > Time.current

    challenge
  end
end
