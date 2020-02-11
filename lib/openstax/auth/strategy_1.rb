require 'json'
require 'active_support'
require 'active_support/core_ext/object/blank'

module OpenStax
  module Auth
    module Strategy1

      extend self

      delegate :cookie_name, :secret_key, :secret_salt,
               to: :configuration

      def user_uuid(request)
        (decrypt(request) || {}).dig("user", "uuid")
      end

      # https://github.com/rails/rails/blob/4-2-stable/activesupport/lib/active_support/message_encryptor.rb#L90
      def decrypt(request)
        cookie = request.cookies[cookie_name]
        return {} unless cookie.present?

        begin
          encryptor.decrypt_and_verify(cookie)
        rescue ActiveSupport::MessageVerifier::InvalidSignature,
               ActiveSupport::MessageEncryptor::InvalidMessage
          {}
        end
      end

      private

      def configuration
        OpenStax::Auth.configuration.strategy1
      end

      # Not thread-safe
      def encryptor
        @encryptor ||= begin
          cipher        = 'aes-256-cbc'
          signed_salt   = "signed encrypted #{secret_salt}"
          key_generator = ActiveSupport::KeyGenerator.new(secret_key, iterations: 1000)
          secret        = key_generator.generate_key(secret_salt)[
            0, OpenSSL::Cipher.new(cipher).key_len
          ]
          sign_secret   = key_generator.generate_key(signed_salt)
          ActiveSupport::MessageEncryptor.new(secret, sign_secret, cipher: cipher, serializer: JSON)
        end
      end

      def reset_config
        @encryptor = nil
      end
    end
  end
end
