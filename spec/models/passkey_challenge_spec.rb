# frozen_string_literal: true

require 'rails_helper'

RSpec.describe PasskeyChallenge do
  let!(:challenge) do
    described_class.create!(challenge: 'random challenge', ceremony: 'authentication', expires_at: 5.minutes.from_now)
  end

  it 'returns a challenge only once' do
    expect(described_class.consume!(challenge.id, ceremony: 'authentication')).to eq challenge
    expect(described_class.consume!(challenge.id, ceremony: 'authentication')).to be_nil
  end

  it 'rejects the other ceremony and consumes the challenge' do
    expect(described_class.consume!(challenge.id, ceremony: 'registration')).to be_nil
    expect(described_class.exists?(challenge.id)).to be false
  end

  it 'rejects an expired challenge' do
    challenge.update!(expires_at: 1.second.ago)
    expect(described_class.consume!(challenge.id, ceremony: 'authentication')).to be_nil
  end
end
