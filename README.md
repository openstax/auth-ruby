# openstax_auth

**This is a fork of openstax/auth-rails that eliminates the ActiveSupport dependency as well as the no-longer-used "strategy 1".**

Provides utilities to get user information from cookies within OpenStax rack-based apps.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'openstax_auth', git: 'https://github.com/openstax/auth-ruby.git', ref: 'some_commit_sha_here'
```

(this gem is not published to rubygems)

And then execute:

    $ bundle

## Usage

This gem contains strategies for extracting user information from cookies and tokens.  As OpenStax authentication cookies evolve over time, new strategies will be added and old ones will no longer be used.

### Getting the current user

The simplest option is the top-level helper:

```ruby
OpenStax::Auth.user_uuid(request)
```

It picks the credential like this:

1. If launch tokens are configured (see below) and the request has a non-blank `X-Launch-Token` header, only the launch token is used. An invalid token returns `nil`; it does **not** fall back to the SSO cookie.
2. Otherwise it returns `OpenStax::Auth::Strategy2.user_uuid(request)`, exactly as before.

Apps that don't configure launch tokens get the same behavior as calling Strategy 2 directly.

### Strategy 2

Reads the Accounts SSO token from the `Authorization: Bearer` header or the SSO cookie.

Configure the `strategy_2` settings:

```ruby
OpenStax::Auth.configure do |config|
  config.strategy2.signature_public_key = "blah"
  config.strategy2.encryption_private_key = "blah"
  config.strategy2.cookie_name = "blah"
  config.strategy2.encryption_algorithm = 'dir'
  config.strategy2.encryption_method = 'A256GCM'
  config.strategy2.signature_algorithm = 'RS256'
end
```

And then `require 'openstax/auth/strategy_2'` in the code that needs it.

### Launch tokens

A launch token is a signed JWT (JWS) created by `@openstax/ts-utils` (`createLaunchSigner`) and sent in the `X-Launch-Token` request header. Its JWT header carries `iss`, `kid` and `alg`; its `sub` claim is the user's UUID. The public keys are fetched from `/.well-known/jwks.json` on the `iss` origin.

Configure the trusted domain to turn the feature on:

```ruby
OpenStax::Auth.configure do |config|
  config.launch_token.trusted_domain = 'openstax.org' # required to enable launch tokens

  # Optional, with defaults:
  config.launch_token.jwks_cache_ttl = 3600 # seconds to reuse fetched keys
  config.launch_token.jwks_miss_ttl = 30    # seconds before an unknown kid can trigger another JWKS fetch
  config.launch_token.open_timeout = 2      # JWKS HTTP connect timeout (seconds)
  config.launch_token.read_timeout = 3      # JWKS HTTP read timeout (seconds)
  config.launch_token.clock_skew = 30       # seconds of leeway for exp and nbf
end
```

Then:

```ruby
OpenStax::Auth::LaunchToken.user_uuid(request) # => "uuid" or nil
OpenStax::Auth::LaunchToken.verify(token)      # => claims Hash or nil
```

A token is accepted only if:

- the header `iss` is an `https` URL whose host is `trusted_domain` or a subdomain of it (checked before any network call),
- the payload `iss` equals the header `iss`,
- `alg` is RS256/384/512, PS256/384/512 or ES256/384/512 and matches the JWK's key type (`none` and HS* are rejected),
- the signature verifies against the JWK with the header's `kid`,
- `exp` is present and not past, and `nbf` (if present) is not in the future, allowing `clock_skew`,
- `sub` is a non-empty string.

Any failure, including network errors fetching the JWKS, returns `nil` rather than raising.

Keys are cached in-process (thread-safe) by JWKS URI and `kid`. An unknown `kid` triggers a refetch, but each JWKS URI is fetched at most once per `jwks_miss_ttl`, so random `kid` values can't force a fetch on every request. Redirects from the JWKS URL are not followed.

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
