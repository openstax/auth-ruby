require 'spec_helper'

RSpec.describe OpenStax::Auth::LaunchToken do
  PRIVATE_JWK_PARAMS = %w[d p q dp dq qi].freeze

  def public_jwk(key, kid)
    JSON::JWK.new(key, kid: kid).reject { |name, _| PRIVATE_JWK_PARAMS.include?(name) }
  end

  def sign(claims, key: rsa_key, alg: :RS256, kid: 'key-1', header_iss: iss)
    jwt = JSON::JWT.new(claims)
    jwt.header[:iss] = header_iss unless header_iss.nil?
    jwt.kid = kid unless kid.nil?
    jwt.sign(key, alg).to_s
  end

  def request_with(token)
    headers = token.nil? ? {} : { 'X-Launch-Token' => token }
    OpenStruct.new(headers: headers, cookies: {})
  end

  let(:config) { OpenStax::Auth.configuration.launch_token }
  let(:iss) { 'https://assignments.openstax.org' }
  let(:jwks_uri) { 'https://assignments.openstax.org/.well-known/jwks.json' }
  let(:uuid) { '1b2dc73a-a792-462b-9b0f-59bd22bac26d' }
  let(:now) { Time.now.to_i }
  let(:claims) { { iss: iss, sub: uuid, iat: now, exp: now + 300 } }

  # Generated once; RSA key generation is slow
  RSA_KEY = OpenSSL::PKey::RSA.new(2048)
  OTHER_RSA_KEY = OpenSSL::PKey::RSA.new(2048)
  EC_KEY = OpenSSL::PKey::EC.generate('prime256v1')

  let(:rsa_key) { RSA_KEY }
  let(:jwks_keys) { [public_jwk(rsa_key, 'key-1'), public_jwk(EC_KEY, 'ec-key')] }

  before do
    config.trusted_domain = 'openstax.org'
    described_class.reset_cache!
    allow(described_class).to receive(:fetch_jwks) do
      described_class.parse_jwks({ keys: jwks_keys }.to_json)
    end
  end

  after do
    config.trusted_domain = nil
    described_class.reset_cache!
  end

  describe '.verify' do
    it 'returns the claims for a valid RS256 token' do
      result = described_class.verify(sign(claims))
      expect(result).to include('sub' => uuid, 'iss' => iss)
      expect(described_class).to have_received(:fetch_jwks).with(jwks_uri).once
    end

    it 'returns the claims for a valid ES256 token' do
      token = sign(claims, key: EC_KEY, alg: :ES256, kid: 'ec-key')
      expect(described_class.verify(token)).to include('sub' => uuid)
    end

    it 'accepts the trusted domain itself as the issuer host' do
      token = sign(claims.merge(iss: 'https://openstax.org'), header_iss: 'https://openstax.org')
      expect(described_class.verify(token)).to include('sub' => uuid)
      expect(described_class).to have_received(:fetch_jwks).with('https://openstax.org/.well-known/jwks.json')
    end

    it 'returns nil when trusted_domain is not configured' do
      config.trusted_domain = nil
      expect(described_class.verify(sign(claims))).to be_nil
      expect(described_class).not_to have_received(:fetch_jwks)
    end

    context 'issuer and domain checks' do
      it 'rejects an untrusted domain without fetching' do
        evil = 'https://evil.example.com'
        expect(described_class.verify(sign(claims.merge(iss: evil), header_iss: evil))).to be_nil
        expect(described_class).not_to have_received(:fetch_jwks)
      end

      it 'rejects a look-alike domain without fetching' do
        evil = 'https://evilopenstax.org'
        expect(described_class.verify(sign(claims.merge(iss: evil), header_iss: evil))).to be_nil
        expect(described_class).not_to have_received(:fetch_jwks)
      end

      it 'rejects a trusted domain used as a prefix of another domain' do
        evil = 'https://openstax.org.evil.com'
        expect(described_class.verify(sign(claims.merge(iss: evil), header_iss: evil))).to be_nil
        expect(described_class).not_to have_received(:fetch_jwks)
      end

      it 'rejects a non-https iss without fetching' do
        http = 'http://assignments.openstax.org'
        expect(described_class.verify(sign(claims.merge(iss: http), header_iss: http))).to be_nil
        expect(described_class).not_to have_received(:fetch_jwks)
      end

      it 'rejects a token with no iss in the header' do
        expect(described_class.verify(sign(claims, header_iss: nil))).to be_nil
        expect(described_class).not_to have_received(:fetch_jwks)
      end

      it 'rejects a payload iss that differs from the header iss' do
        token = sign(claims.merge(iss: 'https://other.openstax.org'))
        expect(described_class.verify(token)).to be_nil
      end
    end

    context 'time checks' do
      it 'rejects an expired token' do
        expect(described_class.verify(sign(claims.merge(exp: now - 120)))).to be_nil
      end

      it 'allows an exp within the clock skew' do
        expect(described_class.verify(sign(claims.merge(exp: now - 5)))).to include('sub' => uuid)
      end

      it 'rejects a token with no exp' do
        claims.delete(:exp)
        expect(described_class.verify(sign(claims))).to be_nil
      end

      it 'rejects a non-numeric exp' do
        expect(described_class.verify(sign(claims.merge(exp: 'never')))).to be_nil
      end

      it 'rejects an nbf in the future' do
        expect(described_class.verify(sign(claims.merge(nbf: now + 120)))).to be_nil
      end

      it 'accepts an nbf in the past' do
        expect(described_class.verify(sign(claims.merge(nbf: now - 10)))).to include('sub' => uuid)
      end
    end

    context 'algorithm checks' do
      it 'rejects HS256 without fetching' do
        token = sign(claims, key: 'shared-secret-shared-secret-shared-secret', alg: :HS256)
        expect(described_class.verify(token)).to be_nil
        expect(described_class).not_to have_received(:fetch_jwks)
      end

      it 'rejects alg none without fetching' do
        jwt = JSON::JWT.new(claims)
        jwt.header[:iss] = iss
        jwt.kid = 'key-1'
        expect(jwt.alg).to eq :none
        expect(described_class.verify(jwt.to_s)).to be_nil
        # Also with a fake signature segment, so the format check isn't what stops it
        expect(described_class.verify("#{jwt.to_s}c2ln")).to be_nil
        expect(described_class).not_to have_received(:fetch_jwks)
      end

      it 'rejects an alg that does not match the key type' do
        # ES256 header pointing at an RSA key
        token = sign(claims, key: EC_KEY, alg: :ES256, kid: 'key-1')
        expect(described_class.verify(token)).to be_nil
      end

      it 'rejects a token signed by a different key' do
        expect(described_class.verify(sign(claims, key: OTHER_RSA_KEY))).to be_nil
      end
    end

    context 'claims' do
      it 'rejects a missing sub' do
        claims.delete(:sub)
        expect(described_class.verify(sign(claims))).to be_nil
      end

      it 'rejects a blank sub' do
        expect(described_class.verify(sign(claims.merge(sub: '')))).to be_nil
      end

      it 'rejects a non-string sub' do
        expect(described_class.verify(sign(claims.merge(sub: { uuid: uuid })))).to be_nil
      end
    end

    context 'malformed input' do
      it 'returns nil for garbage' do
        ['', 'bad!', 'a.b', 'a.b.c', 'a.b.c.d.e', nil, 42].each do |token|
          expect(described_class.verify(token)).to be_nil
        end
        expect(described_class).not_to have_received(:fetch_jwks)
      end

      it 'returns nil for a tampered payload' do
        header, _payload, signature = sign(claims).split('.')
        payload = Base64.urlsafe_encode64(claims.merge(sub: 'someone-else').to_json, padding: false)
        expect(described_class.verify([header, payload, signature].join('.'))).to be_nil
      end

      it 'returns nil when the JWKS response is not valid JSON' do
        allow(described_class).to receive(:fetch_jwks) { described_class.parse_jwks('<html>') }
        expect(described_class.verify(sign(claims))).to be_nil
      end

      it 'returns nil when the JWKS fetch fails' do
        allow(described_class).to receive(:fetch_jwks).and_raise(Net::OpenTimeout)
        expect(described_class.verify(sign(claims))).to be_nil
      end
    end

    context 'key caching' do
      let(:clock_time) { [1000.0] }

      before do
        clock = -> { clock_time.first }
        described_class.instance_variable_set(
          :@key_cache, described_class::KeyCache.new(config, clock: clock)
        )
      end

      def advance(seconds)
        clock_time[0] += seconds
      end

      it 'fetches once for repeated verifies' do
        3.times { expect(described_class.verify(sign(claims))).to include('sub' => uuid) }
        expect(described_class).to have_received(:fetch_jwks).once
      end

      it 'refetches after the cache TTL' do
        described_class.verify(sign(claims))
        advance(config.jwks_cache_ttl + 1)
        expect(described_class.verify(sign(claims))).to include('sub' => uuid)
        expect(described_class).to have_received(:fetch_jwks).twice
      end

      it 'refetches on an unknown kid (key rotation)' do
        described_class.verify(sign(claims))
        advance(config.jwks_miss_ttl + 1)

        jwks_keys << public_jwk(OTHER_RSA_KEY, 'key-2')
        token = sign(claims, key: OTHER_RSA_KEY, kid: 'key-2')
        expect(described_class.verify(token)).to include('sub' => uuid)
        expect(described_class).to have_received(:fetch_jwks).twice
      end

      it 'briefly caches misses for unknown kids' do
        expect(described_class.verify(sign(claims, kid: 'nope-1'))).to be_nil
        expect(described_class.verify(sign(claims, kid: 'nope-1'))).to be_nil
        expect(described_class.verify(sign(claims, kid: 'nope-2'))).to be_nil
        expect(described_class).to have_received(:fetch_jwks).once

        # Known keys from that fetch still work during the miss window
        expect(described_class.verify(sign(claims))).to include('sub' => uuid)
        expect(described_class).to have_received(:fetch_jwks).once

        advance(config.jwks_miss_ttl + 1)
        expect(described_class.verify(sign(claims, kid: 'nope-3'))).to be_nil
        expect(described_class).to have_received(:fetch_jwks).twice
      end

      it 'throttles fetches after a failed fetch' do
        allow(described_class).to receive(:fetch_jwks).and_raise(Errno::ECONNREFUSED)
        2.times { expect(described_class.verify(sign(claims))).to be_nil }
        expect(described_class).to have_received(:fetch_jwks).once
      end
    end
  end

  describe '.user_uuid' do
    it 'returns sub for a valid token' do
      expect(described_class.user_uuid(request_with(sign(claims)))).to eq uuid
    end

    it 'returns nil for an invalid token' do
      expect(described_class.user_uuid(request_with('bad!'))).to be_nil
    end

    it 'returns nil with no header' do
      expect(described_class.user_uuid(request_with(nil))).to be_nil
    end
  end

  describe 'OpenStax::Auth.user_uuid' do
    before { allow(OpenStax::Auth::Strategy2).to receive(:user_uuid).and_return('sso-uuid') }

    it 'uses the launch token when the header is present' do
      expect(OpenStax::Auth.user_uuid(request_with(sign(claims)))).to eq uuid
      expect(OpenStax::Auth::Strategy2).not_to have_received(:user_uuid)
    end

    it 'does not fall back to SSO when the launch token is invalid' do
      expired = sign(claims.merge(exp: now - 120))
      expect(OpenStax::Auth.user_uuid(request_with(expired))).to be_nil
      expect(OpenStax::Auth::Strategy2).not_to have_received(:user_uuid)
    end

    it 'falls back to Strategy2 when there is no launch token header' do
      expect(OpenStax::Auth.user_uuid(request_with(nil))).to eq 'sso-uuid'
    end

    it 'falls back to Strategy2 when the header is blank' do
      expect(OpenStax::Auth.user_uuid(request_with(''))).to eq 'sso-uuid'
    end

    it 'ignores the launch token when launch tokens are not configured' do
      config.trusted_domain = nil
      expect(OpenStax::Auth.user_uuid(request_with(sign(claims)))).to eq 'sso-uuid'
      expect(described_class).not_to have_received(:fetch_jwks)
    end
  end
end
