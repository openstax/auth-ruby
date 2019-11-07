module OpenStax
  module Auth
    class Configuration

      # Settings for strategy 1

      attr_accessor :strategy_1_secret_key
      attr_accessor :strategy_1_secret_salt
      attr_accessor :strategy_1_cookie_name
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
