module OpenStax
  module Auth
    class Configuration

      # settings for strategy 1
      attr_accessor :strategy_1_secret_key
      attr_accessor :strategy_1_secret_salt
      attr_accessor :strategy_1_cookie_name

      # settings for strategy 2
      attr_accessor :strategy_2_signature_public_key
      attr_accessor :strategy_2_encryption_private_key
      attr_accessor :strategy_2_cookie_name
      attr_accessor :strategy_2_encryption_algorithm
      attr_accessor :strategy_2_encryption_method
      attr_accessor :strategy_2_signature_algorithm
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
