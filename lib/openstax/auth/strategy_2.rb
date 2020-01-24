require 'json'
require 'active_support'
require 'active_support/core_ext/object/blank'

module OpenStax
  module Auth
    module Strategy2

      extend self

      def user_uuid(request)
        (decrypt(request) || {}).dig("user", "uuid")
      end

      def decrypt(request)
        cookie = request.cookies[cookie_name]
        return {} unless cookie.present?

        begin
          JSON::JWT.decode(
            JSON::JWT.decode(
              cookie,
              encryption_private_key,
              encryption_algorithm.to_s,
              encryption_method.to_s
            ).plain_text,
            signature_public_key,
            signature_algorithm
          )
        rescue JSON::JWT::Exception, OpenSSL::Cipher::CipherError
          nil
        rescue ActiveSupport::MessageVerifier::InvalidSignature,
          ActiveSupport::MessageEncryptor::InvalidMessage => e
          {}
        end
      end

      private

      def signature_public_key
        signature_public_key = OpenStax::Auth.configuration.strategy_2_signature_public_key
        signature_public_key = OpenSSL::PKey::RSA.new signature_public_key
        raise 'Signature public key is not defined' if signature_public_key.blank?
      end

      def encryption_private_key
        encryption_private_key = OpenStax::Auth.configuration.strategy_2_encryption_private_key
        encryption_private_key = OpenSSL::PKey::RSA.new encryption_private_key
        raise 'Encryption private key is not defined' if encryption_private_key.blank?
      end

      def signature_algorithm
        signature_algorithm = OpenStax::Auth.configuration.strategy_2_signature_algorithm
        raise 'Signature algorithm is not defined' if signature_algorithm.blank?
      end

      def encryption_algorithm
        encryption_algorithm = OpenStax::Auth.configuration.strategy_2_encryption_algorithm
        raise 'Encryption algorithm is not defined' if encryption_algorithm.blank?
      end

      def encryption_method
        encryption_method = OpenStax::Auth.configuration.strategy_2_encryption_method
        raise 'Encryption method is not defined' if encryption_method.blank?
      end
    end
  end
end
