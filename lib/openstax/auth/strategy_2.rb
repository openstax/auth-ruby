require 'json'
require 'json/jwt'
require 'active_support'
require 'active_support/core_ext/object/blank'

module OpenStax
  module Auth
    module Strategy2

      extend self

      def user_uuid(request)
        (decrypt(request) || {}).dig('sub', 'uuid')
      end

      def decrypt(request)
        cookie = request.cookies[cookie_name]
        return {} unless cookie.present?

        begin
          # Decoding is the reverse of what accounts does to encode a cookie:
          # accounts first asymmetric encodes the cookie w/ the signature private
          # key, then it next symmetric encodes that result w/ the encryption
          # private key.

          # Step 1:  symmetric decode the cookie with the encryption private key
          encrypted = JSON::JWT.decode(
            cookie,
            encryption_private_key,
            encryption_algorithm.to_s,
            encryption_method.to_s
          ).plain_text

          # Step 2:  asymmetric decode the previous step with the signature public key
          JSON::JWT.decode(
            encrypted,
            signature_public_key,
            signature_algorithm.to_sym
          )
        rescue JSON::JWT::Exception, OpenSSL::Cipher::CipherError
          nil
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
        signature_public_key = OpenSSL::PKey::RSA.new raw_signature_public_key
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
