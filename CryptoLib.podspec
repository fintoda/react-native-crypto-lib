require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))
secp256k1_compiler_flags = '-DECMULT_GEN_PREC_BITS=4 -DECMULT_WINDOW_SIZE=8 -DENABLE_MODULE_GENERATOR -DENABLE_MODULE_RECOVERY -DENABLE_MODULE_SCHNORRSIG -DENABLE_MODULE_EXTRAKEYS -DSECP256K1_CONTEXT_SIZE=208'

Pod::Spec.new do |s|
  s.name         = "CryptoLib"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = package["homepage"]
  s.license      = package["license"]
  s.authors      = package["author"]

  s.platforms    = { :ios => min_ios_version_supported }
  s.source       = { :git => "https://github.com/fintoda/react-native-crypto-lib.git", :tag => "#{s.version}" }

  s.source_files =  "ios/**/*.{h,m,mm,c,cpp}",
                    "cpp/**/*.{hpp,cpp,c,h}",
                    "crypto/**/*.{h,c}",
                    "vendor/secp256k1-zkp/**/*.h",
                    "vendor/secp256k1-zkp/src/precomputed_ecmult.c",
                    "vendor/secp256k1-zkp/src/precomputed_ecmult_gen.c",
                    "vendor/secp256k1-zkp/src/secp256k1.c"
  
  s.compiler_flags = secp256k1_compiler_flags

# Use install_modules_dependencies helper to install the dependencies if React Native version >=0.71.0.
# See https://github.com/facebook/react-native/blob/febf6b7f33fdb4904669f99d795eba4c0f95d7bf/scripts/cocoapods/new_architecture.rb#L79.
if respond_to?(:install_modules_dependencies, true)
  install_modules_dependencies(s)
else
  s.dependency "React-Core"
end
end
