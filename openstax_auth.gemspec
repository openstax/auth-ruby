lib = File.expand_path("lib", __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "openstax/auth/version"

Gem::Specification.new do |spec|
  spec.name          = "openstax_auth"
  spec.version       = OpenStax::Auth::VERSION
  spec.authors       = ["JP Slavinsky"]
  spec.email         = ["jps@rice.edu"]

  spec.summary       = %q{Provides utilities to get user information from cookies within OpenStax Rails apps.}
  spec.description   = %q{Provides utilities to get user information from cookies within OpenStax Rails apps.}
  spec.homepage      = "https://github.com/openstax/auth-rails"
  spec.license       = "MIT"

  spec.metadata["allowed_push_host"] = "http://rubygems.org"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/openstax/auth-rails"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files         = Dir.chdir(File.expand_path('..', __FILE__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  end
  spec.require_paths = ["lib"]

  spec.add_dependency "activesupport"
  spec.add_dependency "json-jwt"

  spec.add_development_dependency "bundler", "~> 2.0"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"
end
