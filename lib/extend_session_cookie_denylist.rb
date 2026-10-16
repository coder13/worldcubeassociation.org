# frozen_string_literal: true

class ExtendSessionCookieDenylist
  # Membership changes can take up to 1 hr to appear
  # This is only used to automatically extend login sessions.
  # We accept the risk of extending or not extending a session or two for a first-time organizer caught in this caching period in favor of keeping logins performant
  REFRESH_INTERVAL = 1.hour.to_i
  GROUP_TYPES = %w[delegate_regions teams_committees board officers].freeze
  CACHE_KEY = "extend-session-cookie-denylist:v1"
  EMPTY_SET_MEMBER = "empty"

  def restricted?(user_id)
    # Development/test: Redis disabled, fallback of loading user ids
    return load_user_ids.include?(user_id) unless Rails.cache.respond_to?(:redis)

    restricted = cached_restriction(user_id)
    return restricted unless restricted.nil?

    refresh_cache.include?(user_id)
  rescue Redis::BaseError, ConnectionPool::TimeoutError => e
    # Treat Redis failures as denylisted so sessions aren't extended during an outage.
    Rails.error.report(e, handled: true, severity: :warning)
    true
  end

  private def cached_restriction(user_id)
    cached, restricted = Rails.cache.redis.with do |redis|
      redis.multi do |transaction|
        transaction.exists?(CACHE_KEY)
        transaction.sismember(CACHE_KEY, user_id.to_s)
      end
    end
    restricted if cached
  end

  private def refresh_cache
    user_ids = load_user_ids
    temporary_key = "#{CACHE_KEY}:#{SecureRandom.uuid}"

    # The sentinel keeps empty denylists cacheable. Publish the complete set atomically
    # so concurrent requests never see a partially rebuilt list.
    Rails.cache.redis.with do |redis|
      redis.multi do |transaction|
        transaction.sadd(temporary_key, [EMPTY_SET_MEMBER, *user_ids])
        transaction.expire(temporary_key, REFRESH_INTERVAL)
        transaction.rename(temporary_key, CACHE_KEY)
      end
    end

    user_ids
  end

  private def load_user_ids
    organizer_ids = CompetitionOrganizer.distinct.pluck(:organizer_id)
    role_ids = UserRole.active.joins(:group)
                       .where(user_groups: { group_type: GROUP_TYPES })
                       .distinct.pluck(:user_id)

    Set.new((organizer_ids + role_ids).compact).freeze
  end
end
