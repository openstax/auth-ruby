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

      %w[null [] 42 "str" true].each do |raw_payload|
        it "returns nil without fetching for a non-object payload (#{raw_payload})" do
          header, _payload, signature = sign(claims).split('.')
          payload = Base64.urlsafe_encode64(raw_payload, padding: false)
          expect(described_class.verify([header, payload, signature].join('.'))).to be_nil
          expect(described_class).not_to have_received(:fetch_jwks)
        end
      end

      it 'returns nil when the JWKS response is not valid JSON' do
        allow(described_class).to receive(:fetch_jwks) { described_class.parse_jwks('<html>') }
        expect(described_class.verify(sign(claims))).to be_nil
      end

      it 'returns nil when the JWKS fetch fails' do
        allow(described_class).to receive(:fetch_jwks).and_raise(Net::OpenTimeout)
        expect(described_class.verify(sign(claims))).to be_nil
      end

      [Net::HTTPBadResponse, Net::HTTPHeaderSyntaxError, Zlib::DataError].each do |error|
        it "returns nil when the JWKS response raises #{error}" do
          allow(described_class).to receive(:fetch_jwks).and_raise(error)
          expect(described_class.verify(sign(claims))).to be_nil
        end
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

      it 'refetches an expired key even if jwks_miss_ttl is longer than jwks_cache_ttl' do
        original_miss_ttl = config.jwks_miss_ttl
        config.jwks_miss_ttl = config.jwks_cache_ttl * 2
        described_class.verify(sign(claims))
        advance(config.jwks_cache_ttl + 1)
        expect(described_class.verify(sign(claims))).to include('sub' => uuid)
        expect(described_class).to have_received(:fetch_jwks).twice
      ensure
        config.jwks_miss_ttl = original_miss_ttl
      end

      it 'stops trusting a key that was removed from the JWKS at the next refresh' do
        expect(described_class.verify(sign(claims))).to include('sub' => uuid)
        advance(config.jwks_miss_ttl + 1)

        # key-1 is retired and key-2 is added; a key-2 token triggers the refresh
        jwks_keys.replace([public_jwk(OTHER_RSA_KEY, 'key-2')])
        expect(described_class.verify(sign(claims, key: OTHER_RSA_KEY, kid: 'key-2'))).to include('sub' => uuid)
        expect(described_class.verify(sign(claims))).to be_nil
      end

      it 'keeps cached keys when a refresh returns no keys' do
        expect(described_class.verify(sign(claims))).to include('sub' => uuid)
        advance(config.jwks_miss_ttl + 1)

        jwks_keys.clear
        expect(described_class.verify(sign(claims, kid: 'key-2'))).to be_nil
        expect(described_class.verify(sign(claims))).to include('sub' => uuid)
        expect(described_class).to have_received(:fetch_jwks).twice
      end

      it 'maps issuer spellings to one canonical JWKS URI so they share the miss throttle' do
        [
          'https://user1@assignments.openstax.org',
          'https://user2:pw@ASSIGNMENTS.OpenStax.org:443',
          'https://assignments.openstax.org/some/path?q=1#frag'
        ].each do |variant|
          token = sign(claims.merge(iss: variant), header_iss: variant, kid: 'nope')
          expect(described_class.verify(token)).to be_nil
        end
        expect(described_class).to have_received(:fetch_jwks).once
        expect(described_class).to have_received(:fetch_jwks).with(jwks_uri)
      end

      it 'keeps a non-default port in the JWKS URI' do
        port_iss = 'https://assignments.openstax.org:8443'
        described_class.verify(sign(claims.merge(iss: port_iss), header_iss: port_iss))
        expect(described_class).to have_received(:fetch_jwks)
          .with('https://assignments.openstax.org:8443/.well-known/jwks.json')
      end

      it 'bounds its bookkeeping when many distinct issuers fail' do
        stub_const("#{described_class}::KeyCache::MAX_ENTRIES", 5)
        allow(described_class).to receive(:fetch_jwks).and_raise(SocketError)

        20.times do |i|
          host_iss = "https://nope-#{i}.openstax.org"
          described_class.verify(sign(claims.merge(iss: host_iss), header_iss: host_iss))
        end

        cache = described_class.instance_variable_get(:@key_cache)
        expect(described_class).to have_received(:fetch_jwks).exactly(20).times
        expect(cache.instance_variable_get(:@fetched_at).size).to be <= 5
        expect(cache.instance_variable_get(:@uri_locks).size).to eq described_class::KeyCache::LOCK_STRIPES
      end

      it 'keeps throttling the newest failures when pruning' do
        stub_const("#{described_class}::KeyCache::MAX_ENTRIES", 5)
        allow(described_class).to receive(:fetch_jwks).and_raise(SocketError)

        hosts = (0...8).map { |i| "https://nope-#{i}.openstax.org" }
        hosts.each do |host_iss|
          advance(1)
          described_class.verify(sign(claims.merge(iss: host_iss), header_iss: host_iss))
        end
        described_class.verify(sign(claims.merge(iss: hosts.last), header_iss: hosts.last))

        expect(described_class).to have_received(:fetch_jwks).exactly(8).times
      end
    end
  end

  describe '.fetch_jwks' do
    let(:http) { instance_double(Net::HTTP) }

    before do
      allow(described_class).to receive(:fetch_jwks).and_call_original
      allow(Net::HTTP).to receive(:start).and_yield(http)
    end

    def response(klass, code, body = nil)
      klass.new('1.1', code, '').tap do |res|
        allow(res).to receive(:body).and_return(body)
      end
    end

    it 'GETs the JWKS over TLS with the configured timeouts' do
      allow(http).to receive(:request).and_return(response(Net::HTTPOK, '200', { keys: jwks_keys }.to_json))

      keys = described_class.fetch_jwks(jwks_uri)

      expect(keys.keys).to contain_exactly('key-1', 'ec-key')
      expect(Net::HTTP).to have_received(:start).with(
        'assignments.openstax.org', 443,
        use_ssl: true, open_timeout: config.open_timeout, read_timeout: config.read_timeout
      )
      expect(http).to have_received(:request) do |req|
        expect(req).to be_a(Net::HTTP::Get)
        expect(req.path).to eq '/.well-known/jwks.json'
      end
    end

    it 'returns no keys for an error status' do
      allow(http).to receive(:request).and_return(response(Net::HTTPInternalServerError, '500', 'oops'))
      expect(described_class.fetch_jwks(jwks_uri)).to eq({})
    end

    it 'does not follow redirects' do
      redirect = response(Net::HTTPFound, '302')
      redirect['location'] = 'https://evil.example.com/jwks.json'
      allow(http).to receive(:request).and_return(redirect)

      expect(described_class.fetch_jwks(jwks_uri)).to eq({})
      expect(Net::HTTP).to have_received(:start).once
    end

    it 'skips keys without a string kid' do
      body = { keys: [public_jwk(rsa_key, 'key-1').except('kid'), 'junk'] }.to_json
      allow(http).to receive(:request).and_return(response(Net::HTTPOK, '200', body))
      expect(described_class.fetch_jwks(jwks_uri)).to eq({})
    end

    it 'lets timeouts propagate so verify can return nil' do
      allow(Net::HTTP).to receive(:start).and_raise(Net::OpenTimeout)
      expect { described_class.fetch_jwks(jwks_uri) }.to raise_error(Net::OpenTimeout)
      expect(described_class.verify(sign(claims))).to be_nil
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
