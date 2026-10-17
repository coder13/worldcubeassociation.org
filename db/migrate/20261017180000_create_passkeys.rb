# frozen_string_literal: true

class CreatePasskeys < ActiveRecord::Migration[8.1]
  def change
    change_table :users, bulk: true do |t|
      t.string :passkey_user_handle, collation: 'ascii_bin', after: :otp_secret, index: { unique: true }
    end

    create_table :passkeys do |t|
      t.references :user, null: false, foreign_key: true
      # WebAuthn credential IDs can contain 1023 bytes (1364 base64url characters).
      # ASCII keeps the complete, case-sensitive unique index within MySQL limits.
      t.string :credential_id, limit: 1364, collation: 'ascii_bin', null: false, index: { unique: true }
      t.text :public_key, null: false
      t.bigint :sign_count, null: false, default: 0
      t.string :name, null: false
      t.datetime :last_used_at
      t.timestamps
    end

    create_table :passkey_challenges do |t|
      t.references :user, foreign_key: true
      t.string :challenge, null: false
      t.string :ceremony, null: false
      t.datetime :expires_at, null: false, index: true
      t.timestamps
    end
  end
end
