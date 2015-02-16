# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'omniauth/heart/version'

Gem::Specification.new do |spec|
  spec.name          = "omniauth-heart"
  spec.version       = Omniauth::Heart::VERSION
  spec.authors       = ["Dave Hill"]
  spec.email         = ["dwhill@mitre.org"]
  spec.summary       = %q{Heart Working Group Strategy for OmniAuth}
  spec.description   = %q{Heart Working Group Strategy for OmniAuth}
  spec.homepage      = "https://github.com/dhill/omniauth-heart"
  spec.license       = "Apache 2.0"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.7"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "omniauth"
  spec.add_development_dependency "faraday"
  spec.add_development_dependency "json"
  spec.add_development_dependency "jwt"
end
