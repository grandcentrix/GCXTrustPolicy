Pod::Spec.new do |spec|
  spec.name = "GCXTrustPolicy"
  spec.version = "2.0.0"
  spec.summary = "SSL-pinning and trust validation framework for iOS."
  spec.homepage = "https://github.com/grandcentrix/GCXTrustPolicy"
  spec.license =  { :type => 'Apache License, Version 2.0',  :file => 'LICENSE.txt' }
  spec.authors = { "Paul Ehrhardt" => 'paul.ehrhardt@grandcentrix.net' }
  spec.social_media_url = "http://twitter.com/grandcentrix"
  spec.platform = :ios, "8.0"
  spec.source = { git: "https://github.com/grandcentrix/GCXTrustPolicy.git", tag: "v#{spec.version}"}
  spec.source_files = "GCXTrustPolicy/**/*.{swift}"
  spec.swift_version = "5.0"
end
