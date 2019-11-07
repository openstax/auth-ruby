# openstax_auth

[![Build Status](https://travis-ci.org/openstax/auth-rails.svg?branch=master)](https://travis-ci.org/openstax/auth-rails)

Provides utilities to get user information from cookies within OpenStax Rails apps.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'openstax_auth'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install openstax_auth

## Usage

This gem contains strategies for extracting user information from cookies.  As OpenStax authentication cookies evolve over time, new strategies will be added and old ones will no longer be used.

### Strategy 1

The only strategy currently.  Uses a symmetric encryption algorithm from ActiveSupport (modeled after normal Rails secure cookies).

Configure the `strategy_1` settings:

```ruby
OpenStax::Auth.configure do |config|
  config.strategy_1_secret_key = "blah"
  config.strategy_1_secret_salt = "blah"
  config.strategy_1_cookie_name = "blah"
end
```

And then `require 'openstax/auth/strategy_1'` in the code that needs it.

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/[USERNAME]/openstax_auth. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the openstax_auth project’s codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/[USERNAME]/openstax_auth/blob/master/CODE_OF_CONDUCT.md).
