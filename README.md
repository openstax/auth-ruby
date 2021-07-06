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

This gem contains strategies for extracting user information from cookies.  As OpenStax authentication cookies evolve over time, new strategies will be added and old ones will no longer be used.

### Strategy 2

The only strategy in this gem.

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

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
