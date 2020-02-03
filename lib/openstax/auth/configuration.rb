module OpenStax
  module Auth
    class Configuration
      attr_reader :strategy1
      attr_reader :strategy2

      class ConfigFields
        def self.attr_accessor(*vars)
          @@attributes ||= []
          @@attributes.concat vars
          super(*vars)
        end

        def initialize
          @@attributes.each do |v|
            define_singleton_method(v) do
              val = instance_variable_get "@#{v.to_s}".to_sym
              raise "#{v} not set" if val.blank?
              val
            end
          end
        end
      end

      class Strategy1 < ConfigFields
        attr_accessor :secret_key
        attr_accessor :secret_salt
        attr_accessor :cookie_name
      end

      class Strategy2 < ConfigFields
        attr_accessor :signature_public_key
        attr_accessor :encryption_private_key
        attr_accessor :cookie_name
        attr_accessor :encryption_algorithm
        attr_accessor :encryption_method
        attr_accessor :signature_algorithm
      end

      def initialize
        @strategy1 = Strategy1.new
        @strategy2 = Strategy2.new
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
