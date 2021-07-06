module OpenStax
  module Auth
    class Configuration
      attr_reader :strategy2

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

      def initialize
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
