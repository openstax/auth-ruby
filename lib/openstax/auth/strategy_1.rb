require 'json'
require 'active_support'
require 'active_support/core_ext/object/blank'

module OpenStax
  module Auth
    module Strategy1

      extend self

      def user_uuid(request)
        (decrypt(request) || {}).dig("user", "uuid")
      end

      # https://github.com/rails/rails/blob/4-2-stable/activesupport/lib/active_support/message_encryptor.rb#L90
      def decrypt(request)
        cookie_name = OpenStax::Auth.configuration.strategy_1_cookie_name
        raise 'OpenStax::Auth strategy_1_cookie_name is not defined' if cookie_name.blank?

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

      # Not thread-safe
      def encryptor
        @encryptor ||= begin
          key = OpenStax::Auth.configuration.strategy_1_secret_key
          raise 'OpenStax::Auth strategy_1_secret_key is not defined' if key.blank?

          salt = OpenStax::Auth.configuration.strategy_1_secret_salt
          raise 'OpenStax::Auth strategy_1_secret_salt is not defined' if salt.blank?

          cipher        = 'aes-256-cbc'
          signed_salt   = "signed encrypted #{salt}"
          key_generator = ActiveSupport::KeyGenerator.new(key, iterations: 1000)
          secret        = key_generator.generate_key(salt)[
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
