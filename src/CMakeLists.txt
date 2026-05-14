target_sources(${CMAKE_PROJECT_NAME} PRIVATE
        crypto-tss-rsa/RSAPrivateKeyShare.cpp
        crypto-tss-rsa/RSAPublicKey.cpp
        crypto-tss-rsa/RSAKeyMeta.cpp
        crypto-tss-rsa/RSASigShare.cpp
        crypto-tss-rsa/KeyGenParam.cpp
        crypto-tss-rsa/RSASigShareProof.cpp
        crypto-tss-rsa/tss_rsa.cpp
        crypto-tss-rsa/emsa_pss.cpp
        crypto-tss-rsa/proto_gen/tss_rsa.pb.switch.cc
        )

if (PLATFORM STREQUAL "SGX")
    target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
            ${SafeheronCryptoSuitesSgx_INCLUDE_DIRS}/crypto-suites
            )
else()
    find_package(PkgConfig REQUIRED)
    #set(OPENSSL_USE_STATIC_LIBS TRUE)
    find_package(OpenSSL REQUIRED)
    find_package(SafeheronCryptoSuites REQUIRED)

    target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
            ${SafeheronCryptoSuites_INCLUDE_DIRS}
            ${OPENSSL_INCLUDE_DIR}
            /usr/local/include
            )

    target_link_directories(${CMAKE_PROJECT_NAME} PRIVATE /usr/local/lib)

    target_link_libraries(${CMAKE_PROJECT_NAME}
            SafeheronCryptoSuites
            OpenSSL::Crypto
            -ldl
            )
endif()
