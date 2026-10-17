# frozen_string_literal: true

class Passkey < ApplicationRecord
  CREDENTIAL_ID_MAX_LENGTH = 1364
  CREDENTIAL_ID_FORMAT = /\A[A-Za-z0-9_-]{1,#{CREDENTIAL_ID_MAX_LENGTH}}\z/
  NAME_MAX_LENGTH = 100

  belongs_to :user

  validates :credential_id, :public_key, :name, presence: true
  validates :credential_id, uniqueness: { case_sensitive: true }, length: { maximum: CREDENTIAL_ID_MAX_LENGTH }
  validates :name, length: { maximum: NAME_MAX_LENGTH }
  validates :sign_count, numericality: { only_integer: true, greater_than_or_equal_to: 0 }
end
