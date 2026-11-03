module OpenStax
  module Auth
    class Configuration
      attr_reader :strategy2, :launch_token

      class ConfigFields
        def self.attr_accessor(*vars, required: false)
          super(*vars)
          vars.each do |v|
            define_singleton_method(v) do
              val = instance_variable_get "@#{v.to_s}".to_sym
              raise "#{v} not set" if (val.nil? || val == "") && required
              val
            end
          end
        end
      end

      class Strategy2 < ConfigFields
        attr_accessor :signature_public_key, required: true
        attr_accessor :encryption_private_key, required: true
        attr_accessor :cookie_name, required: true
        attr_accessor :encryption_algorithm, required: true
        attr_accessor :encryption_method, required: true
        attr_accessor :signature_algorithm, required: true
      end

      # Settings for verifying OpenStax launch tokens (signed JWTs sent in the
      # `X-Launch-Token` request header). Unlike strategy2, nothing here raises
      # when unset: if `trusted_domain` is blank the feature is off.
      class LaunchToken
        DEFAULTS = {
          # Keys fetched from a JWKS are reused for this many seconds
          jwks_cache_ttl: 3600,
          # After fetching a JWKS URI, an unknown kid (or a failed fetch) won't
          # trigger another fetch of that URI for this many seconds
          jwks_miss_ttl: 30,
          # HTTP timeouts (seconds) for fetching the JWKS
          open_timeout: 2,
          read_timeout: 3,
          # Allowed clock skew (seconds) when checking exp and nbf
          clock_skew: 30
        }.freeze

        # The domain trusted to host launch token keys, eg "openstax.org".
        # The JWKS host must equal it or be a subdomain of it.
        attr_accessor :trusted_domain
        attr_writer(*DEFAULTS.keys)

        DEFAULTS.each do |name, default|
          define_method(name) do
            value = instance_variable_get("@#{name}")
            value.nil? ? default : value
          end
        end

        def configured?
          !trusted_domain.nil? && !trusted_domain.to_s.strip.empty?
        end
      end

      def initialize
        @strategy2 = Strategy2.new
        @launch_token = LaunchToken.new
      end
    end

    class << self
      ###########################################################################
      #
      # Configuration machinery.
      #
      # To configure OpenStax Auth, put the following code in your
      # application's initialization logic
      # (eg. in the config/initializers in a Rails app)
      #
      #   OpenStax::Auth.configure do |config|
      #     config.<parameter name> = <parameter value>
      #     ...
      #   end
      #
      def configure
        yield configuration
      end

      def configuration
        @configuration ||= Configuration.new
      end
    end
  end
end
