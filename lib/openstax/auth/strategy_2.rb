require 'json/jwt'
require 'forwardable'

module OpenStax
  module Auth
    module Strategy2
      extend Forwardable
      extend self

      def_delegators :configuration,
                     :cookie_name,
                     :signature_public_key,
                     :signature_algorithm,
                     :encryption_private_key,
                     :encryption_algorithm,
                     :encryption_method

      def user_uuid(request)
        (decrypt(request) || {}).dig('sub', 'uuid')
      end

      def decrypt(request)
        auth_header = request.headers['Authorization'] || ''
        cookie = auth_header.start_with? 'Bearer ' ?
          auth_header.sub('Bearer ', '') : request.cookies[cookie_name]
        return if cookie.nil? || cookie.empty?

        begin
          # Decoding is the reverse of what accounts does to encode a cookie:
          # accounts first asymmetric encodes the cookie w/ the signature private
          # key, then it next symmetric encodes that result w/ the encryption
          # private key.

          # Step 1:  symmetric decode the cookie with the encryption private key
          encrypted = JSON::JWT.decode(
            cookie,
            rsa_encryption_private_key,
            encryption_algorithm.to_s,
            encryption_method.to_s
          ).plain_text

          # Step 2:  asymmetric decode the previous step with the signature public key
          JSON::JWT.decode(
            encrypted,
            rsa_signature_public_key,
            signature_algorithm.to_sym
          )
        rescue JSON::JWT::Exception, OpenSSL::Cipher::CipherError
          nil
        end
      end

      private

      def configuration
        OpenStax::Auth.configuration.strategy2
      end

      def rsa_signature_public_key
        OpenSSL::PKey::RSA.new signature_public_key
      end

      def rsa_encryption_private_key
        OpenSSL::PKey::RSA.new encryption_private_key rescue encryption_private_key
      end
    end
  end
end
