# frozen_string_literal: true

require "rails_helper"

RSpec.feature "Sign in with 2FA" do
  context 'Signing in without 2FA' do
    let(:fool) { create(:user) }

    it 'works for a fool' do
      visit "/users/sign_in"
      fill_in "Email", with: fool.email
      fill_in "user[password]", with: "wca"
      click_button "Sign in"
      expect(page).to have_text "Signed in successfully"
    end
  end

  context 'Signing in with 2FA' do
    let(:user) { create(:user, :with_2fa) }

    it 'works with an otp' do
      visit "/users/sign_in"
      fill_in "Email", with: user.email
      fill_in "user[password]", with: "wca"
      click_button "Sign in"
      expect(page).to have_text "Enter your two-factor authentication code"
      fill_in "user[otp_attempt]", with: user.current_otp
      click_button "Confirm code"
      expect(page).to have_text "Signed in successfully"
    end

    it 'works with a backup codes' do
      codes = user.generate_otp_backup_codes!
      user.save!
      visit "/users/sign_in"
      fill_in "Email", with: user.email
      fill_in "user[password]", with: "wca"
      click_button "Sign in"
      expect(page).to have_text "Enter your two-factor authentication code"
      fill_in "user[otp_attempt]", with: codes.first
      click_button "Confirm code"
      expect(page).to have_text "Signed in successfully"
    end

    it 'requires 2FA after a password reset' do
      reset_token = user.send_reset_password_instructions

      visit edit_user_password_path(reset_password_token: reset_token)
      fill_in "user[password]", with: "new-password"
      fill_in "user[password_confirmation]", with: "new-password"
      click_button "Change my password"

      expect(page).to have_current_path(new_user_session_path)

      fill_in "Email", with: user.email
      fill_in "user[password]", with: "new-password"
      click_button "Sign in"

      expect(page).to have_text "Enter your two-factor authentication code"
    end
  end
end
