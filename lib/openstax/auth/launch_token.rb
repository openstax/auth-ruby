require 'json/jwt'
require 'base64'
require 'net/http'
require 'uri'
require 'openstax/auth/configuration'

module OpenStax
  module Auth
    # Verifies OpenStax launch tokens: JWS tokens signed by @openstax/ts-utils
    # (`createLaunchSigner`) and sent in the `X-Launch-Token` request header.
    #
    # The JWT header carries `iss`, `kid` and `alg`. The signing keys are
    # published at `/.well-known/jwks.json` on the `iss` origin, which must be
    # on the configured trusted domain. `sub` is the user's UUID.
    module LaunchToken
      HEADER_NAME = 'X-Launch-Token'.freeze

      ALLOWED_ALGORITHMS = %w[
        RS256 RS384 RS512
        PS256 PS384 PS512
        ES256 ES384 ES512
      ].freeze

      EC_CURVES = { 'ES256' => 'P-256', 'ES384' => 'P-384', 'ES512' => 'P-521' }.freeze

      COMPACT_JWS = /\A[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\z/

      RESCUED_ERRORS = [
        JSON::JWT::Exception,
        JSON::ParserError,
        ArgumentError,       # bad base64, bad key params
        TypeError,
        OpenSSL::OpenSSLError,
        URI::Error,
        SocketError,
        SystemCallError,     # ECONNREFUSED and friends
        IOError,
        Timeout::Error,      # includes Net::OpenTimeout and Net::ReadTimeout
        Net::ProtocolError
      ].freeze

      extend self

      # Returns the user UUID (`sub`) from a valid launch token in the request's
      # `X-Launch-Token` header, or nil.
      def user_uuid(request)
        claims = verify(token_from(request))
        claims && claims['sub']
      end

      # Returns the raw `X-Launch-Token` header value, or nil if absent/blank.
      def token_from(request)
        token = request.headers[HEADER_NAME]
        token = token.to_s.strip
        token.empty? ? nil : token
      end

      def configured?
        configuration.configured?
      end

      # Verifies a launch token and returns its claims as a Hash, or nil if the
      # token is missing, malformed, untrusted, expired or otherwise invalid.
      def verify(token)
        return nil unless configured?
        return nil unless token.is_a?(String) && COMPACT_JWS.match?(token)

        header = JSON.parse(Base64.urlsafe_decode64(token.split('.').first))
        return nil unless header.is_a?(Hash)

        alg = header['alg']
        kid = header['kid']
        iss = header['iss']
        return nil unless ALLOWED_ALGORITHMS.include?(alg)
        return nil unless kid.is_a?(String) && !kid.empty?

        # Trust is checked before any network call
        jwks_uri = trusted_jwks_uri(iss)
        return nil if jwks_uri.nil?

        jwk = key_cache.fetch(jwks_uri, kid) { |uri| fetch_jwks(uri) }
        return nil if jwk.nil? || !key_matches_alg?(jwk, alg)

        public_key = public_key_for(jwk)
        return nil if public_key.nil?

        jwt = JSON::JWT.decode(token, public_key, [alg.to_sym])
        claims = jwt.to_hash
        valid_claims?(claims, iss) ? claims : nil
      rescue *RESCUED_ERRORS
        nil
      end

      # Returns the JWKS URI for an `iss` value, or nil unless `iss` is an
      # https URL whose host is the trusted domain or one of its subdomains.
      def trusted_jwks_uri(iss)
        return nil unless iss.is_a?(String) && !iss.empty?

        issuer = URI.parse(iss)
        return nil unless issuer.is_a?(URI::HTTPS) && issuer.host

        host = issuer.host.downcase
        return nil unless trusted_host?(host)

        # Like JS `new URL('/.well-known/jwks.json', iss)`, but built from the
        # canonical origin (no userinfo, query or fragment, lowercase host,
        # default port omitted). Every spelling of an issuer then maps to one
        # cache key, so varying it can't bypass the miss throttle.
        port = issuer.port == issuer.default_port ? '' : ":#{issuer.port}"
        "https://#{host}#{port}/.well-known/jwks.json"
      rescue URI::Error
        nil
      end

      def trusted_host?(host)
        domain = configuration.trusted_domain.to_s.strip.downcase.sub(/\A\./, '')
        host = host.to_s.downcase
        return false if domain.empty? || host.empty?

        host == domain || host.end_with?(".#{domain}")
      end

      # Fetches a JWKS document and returns { kid => JSON::JWK }. Redirects are
      # not followed. Stubbed in specs.
      def fetch_jwks(jwks_uri)
        uri = URI.parse(jwks_uri)
        response = Net::HTTP.start(
          uri.host, uri.port,
          use_ssl: true,
          open_timeout: configuration.open_timeout,
          read_timeout: configuration.read_timeout
        ) do |http|
          http.request(Net::HTTP::Get.new(uri.request_uri, 'Accept' => 'application/json'))
        end
        return {} unless response.is_a?(Net::HTTPSuccess)

        parse_jwks(response.body)
      end

      def parse_jwks(body)
        parsed = JSON.parse(body.to_s)
        return {} unless parsed.is_a?(Hash) && parsed['keys'].is_a?(Array)

        parsed['keys'].each_with_object({}) do |params, keys|
          next unless params.is_a?(Hash) && params['kid'].is_a?(String)

          keys[params['kid']] = JSON::JWK.new(params)
        end
      end

      def key_cache
        @key_cache_lock ||= Mutex.new
        @key_cache_lock.synchronize { @key_cache ||= KeyCache.new(configuration) }
      end

      # Clears cached keys (for specs, or after changing configuration).
      def reset_cache!
        @key_cache_lock ||= Mutex.new
        @key_cache_lock.synchronize { @key_cache = nil }
      end

      # In-process, thread-safe cache of JWKS keys keyed by (jwks_uri, kid).
      #
      # - A hit within `jwks_cache_ttl` is served without a fetch.
      # - On a miss, the JWKS URI is fetched (one fetch at a time per URI, so
      #   concurrent requests at startup share a single fetch) and every key in
      #   the set is cached.
      # - After a fetch, unknown kids for that URI return nil without another
      #   fetch for `jwks_miss_ttl`. This also throttles a failing endpoint, so
      #   random kids can't force a fetch on every request.
      class KeyCache
        MAX_ENTRIES = 1000
        # Fetches are serialized per URI through a fixed pool of mutexes
        # (striped by URI), so the lock bookkeeping stays bounded however many
        # distinct issuers requests name.
        LOCK_STRIPES = 64

        def initialize(config, clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
          @config = config
          @clock = clock
          @lock = Mutex.new
          @keys = {}          # [jwks_uri, kid] => [jwk, expires_at]
          @fetched_at = {}    # jwks_uri => time of last fetch attempt
          @uri_locks = Array.new(LOCK_STRIPES) { Mutex.new }
        end

        # Yields the jwks_uri to a block returning { kid => jwk } when a fetch
        # is needed. Returns the JWK or nil.
        def fetch(jwks_uri, kid)
          cached = lookup(jwks_uri, kid)
          return cached unless cached.nil?

          uri_lock(jwks_uri).synchronize do
            # Another thread may have fetched while we waited
            cached = lookup(jwks_uri, kid)
            return cached unless cached.nil?
            return nil if recently_fetched?(jwks_uri)

            keys = begin
              yield(jwks_uri) || {}
            ensure
              @lock.synchronize do
                @fetched_at[jwks_uri] = now
                prune if @fetched_at.size > MAX_ENTRIES
              end
            end
            store(jwks_uri, keys)
            lookup(jwks_uri, kid)
          end
        end

        private

        def lookup(jwks_uri, kid)
          @lock.synchronize do
            jwk, expires_at = @keys[[jwks_uri, kid]]
            jwk if jwk && expires_at > now
          end
        end

        def recently_fetched?(jwks_uri)
          @lock.synchronize do
            fetched_at = @fetched_at[jwks_uri]
            !fetched_at.nil? && now - fetched_at < @config.jwks_miss_ttl
          end
        end

        def store(jwks_uri, keys)
          @lock.synchronize do
            expires_at = now + @config.jwks_cache_ttl
            keys.each { |kid, jwk| @keys[[jwks_uri, kid]] = [jwk, expires_at] }
            prune if @keys.size > MAX_ENTRIES || @fetched_at.size > MAX_ENTRIES
          end
        end

        def uri_lock(jwks_uri)
          @uri_locks[jwks_uri.hash % LOCK_STRIPES]
        end

        # Called with @lock held
        def prune
          time = now
          @keys.delete_if { |_, (_, expires_at)| expires_at <= time }
          @fetched_at.delete_if { |_, fetched_at| time - fetched_at >= @config.jwks_miss_ttl }
          # Still over the cap: keep the newest entries
          if @fetched_at.size > MAX_ENTRIES
            @fetched_at = @fetched_at.sort_by { |_, fetched_at| -fetched_at }.first(MAX_ENTRIES).to_h
          end
          if @keys.size > MAX_ENTRIES
            @keys = @keys.sort_by { |_, (_, expires_at)| -expires_at }.first(MAX_ENTRIES).to_h
          end
        end

        def now
          @clock.call
        end
      end

      private

      def configuration
        OpenStax::Auth.configuration.launch_token
      end

      # Malformed JWK params can raise almost anything from json-jwt/OpenSSL
      def public_key_for(jwk)
        jwk.to_key
      rescue StandardError
        nil
      end

      def key_matches_alg?(jwk, alg)
        return false if jwk['alg'] && jwk['alg'] != alg
        return false if jwk['use'] && jwk['use'] != 'sig'

        case alg[0, 2]
        when 'RS', 'PS' then jwk['kty'] == 'RSA'
        when 'ES' then jwk['kty'] == 'EC' && jwk['crv'] == EC_CURVES[alg]
        else false
        end
      end

      def valid_claims?(claims, header_iss)
        return false unless claims['iss'] == header_iss

        sub = claims['sub']
        return false unless sub.is_a?(String) && !sub.strip.empty?

        now = Time.now.to_i
        skew = configuration.clock_skew.to_i

        exp = claims['exp']
        return false unless exp.is_a?(Numeric) && now < exp + skew

        nbf = claims['nbf']
        return false unless nbf.nil? || (nbf.is_a?(Numeric) && now + skew >= nbf)

        true
      end
    end
  end
end
