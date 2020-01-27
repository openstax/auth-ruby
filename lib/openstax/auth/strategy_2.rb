require 'json'
require 'json/jwt'
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
          encrypted = JSON::JWT.decode(
            cookie,
            encryption_private_key,
            encryption_algorithm.to_s,
            encryption_method.to_s
          ).plain_text

          JSON::JWT.decode(
            encrypted,
            signature_public_key,
            signature_algorithm
          )
        rescue JSON::JWT::Exception, OpenSSL::Cipher::CipherError => ex
          nil
        #rescue ActiveSupport::MessageVerifier::InvalidSignature,
        #  ActiveSupport::MessageEncryptor::InvalidMessage => e
        #  {}
        end
      end

      private

      def cookie_name
        cookie_name = OpenStax::Auth.configuration.strategy_2_cookie_name
        raise 'Signature public key is not defined' if cookie_name.blank?

        cookie_name
      end
      def signature_public_key
        raw_signature_public_key = OpenStax::Auth.configuration.strategy_2_signature_public_key
        signature_public_key = OpenSSL::PKey::RSA.new raw_signature_public_key \
          rescue raw_signature_public_key      #use literal key
        raise 'Signature public key is not defined' if signature_public_key.blank?

        signature_public_key
      end

      def encryption_private_key
        raw_encryption_private_key = OpenStax::Auth.configuration.strategy_2_encryption_private_key
        encryption_private_key = OpenSSL::PKey::RSA.new raw_encryption_private_key \
          rescue raw_encryption_private_key     #use literal key
        raise 'Encryption private key is not defined' if encryption_private_key.blank?

        encryption_private_key
      end

      def signature_algorithm
        signature_algorithm = OpenStax::Auth.configuration.strategy_2_signature_algorithm
        raise 'Signature algorithm is not defined' if signature_algorithm.blank?

        signature_algorithm
      end

      def encryption_algorithm
        encryption_algorithm = OpenStax::Auth.configuration.strategy_2_encryption_algorithm
        raise 'Encryption algorithm is not defined' if encryption_algorithm.blank?

        encryption_algorithm
      end

      def encryption_method
        encryption_method = OpenStax::Auth.configuration.strategy_2_encryption_method
        raise 'Encryption method is not defined' if encryption_method.blank?

        encryption_method
      end
    end
  end
end
