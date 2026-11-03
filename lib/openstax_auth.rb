require "openstax/auth/version"
require "openstax/auth/configuration"
require "openstax/auth/strategy_2"
require "openstax/auth/launch_token"

module OpenStax
  module Auth
    class << self
      # Returns the current user's UUID, or nil.
      #
      # If launch tokens are configured and the request has an `X-Launch-Token`
      # header, only that token is used: an invalid token returns nil and does
      # not fall back to the SSO cookie. Otherwise this is the same as
      # `Strategy2.user_uuid(request)`.
      def user_uuid(request)
        if LaunchToken.configured? && LaunchToken.token_from(request)
          LaunchToken.user_uuid(request)
        else
          Strategy2.user_uuid(request)
        end
      end
    end
  end
end
