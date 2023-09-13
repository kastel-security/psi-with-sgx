cmake_minimum_required (VERSION 2.6)
project (sgx)
set(CMAKE_CXX_FLAGS "--std=c++17")

set(SGX_SDK "/opt/intel/sgxsdk")
set(SGX_MODE "HW")
set(SGX_ARCH "x64")

#ifeq ($(shell getconf LONG_BIT), 32)
#	SGX_ARCH := x86
#else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
#	SGX_ARCH := x86
#endifls

if( "${SGX_ARCH}" STREQUAL "x86")
	set(SGX_COMMON_CFLAGS "-m32")
	set(SGX_LIBRARY_PATH "${SGX_SDK}/lib")
	set(SGX_ENCLAVE_SIGNER "${SGX_SDK}/bin/x86/sgx_sign")
	set(SGX_EDGER8R "${SGX_SDK}/bin/x86/sgx_edger8r")
else()
	set(SGX_COMMON_CFLAGS "-m64")
	set(SGX_LIBRARY_PATH "${SGX_SDK}/lib64")
	set(SGX_ENCLAVE_SIGNER "${SGX_SDK}/bin/x64/sgx_sign")
	set(SGX_EDGER8R "${SGX_SDK}/bin/x64/sgx_edger8r")
endif()


set(CMAKE_SKIP_BUILD_RPATH true)
if( "${SGX_MODE}" STREQUAL "HW")
	set(SGX_LIBS ${SGX_LIBRARY_PATH}/libsgx_uae_service.so ${SGX_LIBRARY_PATH}/libsgx_urts.so)
    set(SGX_ENCLAVE_TRTS_LIB ${SGX_LIBRARY_PATH}/libsgx_trts.a)
    set(SGX_ENCLAVE_SERVICE_LIB ${SGX_LIBRARY_PATH}/libsgx_tservice.a)
else()
	set(SGX_LIBS ${SGX_LIBRARY_PATH}/libsgx_uae_service_sim.so ${SGX_LIBRARY_PATH}/libsgx_urts_sim.so)
    set(SGX_ENCLAVE_TRTS_LIB ${SGX_LIBRARY_PATH}/libsgx_trts_sim.a)
    set(SGX_ENCLAVE_SERVICE_LIB ${SGX_LIBRARY_PATH}/libsgx_tservice_sim.a)
endif()

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
# add_definitions(-DNDEBUG -UEDEBUG -UDEBUG)
add_definitions(-DNDEBUG -DEDEBUG)

add_compile_options(-O3 -g -march=broadwell)
add_compile_options(-fPIC -Wno-attributes)

add_subdirectory(GoogleMessages)


############################### Enclave ###############################
function(add_enclave TARGET_NAME ENCLAVE_SOURCE ENCLAVE_NAME ENCLAVE_UNTRUSTED_DIR_NAME)

    set(ENCLAVE_TRUSTED_DIR ${CMAKE_CURRENT_BINARY_DIR}/${TARGET_NAME}-trusted)
    set(ENCLAVE_UNTRUSTED_DIR ${CMAKE_CURRENT_BINARY_DIR}/${TARGET_NAME}-untrusted)
    file(MAKE_DIRECTORY ${ENCLAVE_TRUSTED_DIR})
    file(MAKE_DIRECTORY ${ENCLAVE_UNTRUSTED_DIR})
    set(${ENCLAVE_UNTRUSTED_DIR_NAME} "${ENCLAVE_UNTRUSTED_DIR}" PARENT_SCOPE)
    add_custom_command(
        OUTPUT
            ${ENCLAVE_TRUSTED_DIR}/${ENCLAVE_NAME}_t.c ${ENCLAVE_TRUSTED_DIR}/${ENCLAVE_NAME}_t.h
            ${ENCLAVE_UNTRUSTED_DIR}/${ENCLAVE_NAME}_u.c ${ENCLAVE_UNTRUSTED_DIR}/${ENCLAVE_NAME}_u.h
        COMMAND ${SGX_EDGER8R} --untrusted --trusted --untrusted-dir ${ENCLAVE_UNTRUSTED_DIR} --trusted-dir ${ENCLAVE_TRUSTED_DIR}
        ${ENCLAVE_SOURCE}/${ENCLAVE_NAME}.edl --search-path ${ENCLAVE_SOURCE} --search-path ${SGX_SDK}/include
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        DEPENDS ${ENCLAVE_SOURCE}/${ENCLAVE_NAME}.edl
        COMMENT "Generating Enclave stubs")

    add_library( ${TARGET_NAME} SHARED
        ${ENCLAVE_TRUSTED_DIR}/${ENCLAVE_NAME}_t.c
        ${ENCLAVE_SOURCE}/${ENCLAVE_NAME}.cpp
        Enclave_shared/IASReport.cpp
        Enclave_shared/UtilityFunctions.cpp
        Enclave_shared/Base64.cpp
    )
    target_compile_definitions( ${TARGET_NAME} PRIVATE ENCLAVE )
    target_compile_options( ${TARGET_NAME} PRIVATE -std=c++17 )

    # To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
    #    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
    #       so that the whole content of trts is included in the enclave.
    #    2. For other libraries, you just need to pull the required symbols.
    #       Use `--start-group' and `--end-group' to link these libraries.
    # Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
    # Otherwise, you may get some undesirable errors.
    target_link_libraries(${TARGET_NAME} -nostdlib -nodefaultlibs -nostartfiles
        -Wl,--whole-archive ${SGX_ENCLAVE_TRTS_LIB} -Wl,--no-whole-archive
        -Wl,--start-group  -L${CMAKE_CURRENT_SOURCE_DIR}/dep/mbedtls-SGX/build/mbedtls_SGX-2.6.0/lib/ -lmbedtls_SGX_t
        ${SGX_LIBRARY_PATH}/libsgx_tstdc.a
        ${SGX_LIBRARY_PATH}/libsgx_tcxx.a
        #-lsgx_tstdcxx
        # /usr/lib/x86_64-linux-gnu/libjsoncpp.a
        ${SGX_LIBRARY_PATH}/libsgx_tkey_exchange.a
        ${SGX_LIBRARY_PATH}/libsgx_tcrypto.a ${SGX_ENCLAVE_SERVICE_LIB} -Wl,--end-group
        -Wl,-Bstatic -Wl,-Bsymbolic
	#-Wl,--no-undefined
        -Wl,-pie,-eenclave_entry -Wl,--export-dynamic
        -Wl,--defsym,__ImageBase=0
        -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/${ENCLAVE_SOURCE}/${ENCLAVE_NAME}.lds
    )
    target_include_directories ( ${TARGET_NAME} PRIVATE
        ${SGX_SDK}/include
        ${SGX_SDK}/include/libcxx
        ${SGX_SDK}/include/tlibc 
        ${SGX_SDK}/include/stlport
        ${SGX_SDK}/include/crypto_px/include
        ${ENCLAVE_TRUSTED_DIR}

        /usr/include/jsoncpp

        Enclave_shared

        dep/mbedtls-SGX/build/mbedtls_SGX-2.6.0/include
    )

    add_custom_target(${TARGET_NAME}-signed ALL
        DEPENDS ${TARGET_NAME}.signed.so)
    add_custom_command(OUTPUT ${TARGET_NAME}.signed.so
                    COMMAND ${SGX_ENCLAVE_SIGNER} sign -key ${ENCLAVE_SOURCE}/${ENCLAVE_NAME}_private.pem
                        -enclave ${CMAKE_CURRENT_BINARY_DIR}/lib${TARGET_NAME}.so
                        -out ${CMAKE_CURRENT_BINARY_DIR}/${TARGET_NAME}.signed.so
                        -config ${ENCLAVE_SOURCE}/${ENCLAVE_NAME}.config.xml
                    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/lib${TARGET_NAME}.so ${ENCLAVE_SOURCE}/${ENCLAVE_NAME}.config.xml ${ENCLAVE_SOURCE}/${ENCLAVE_NAME}_private.pem
                    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                    COMMENT "Signing Enclave"
    )
    add_dependencies(${TARGET_NAME}-signed ${TARGET_NAME})

endfunction()

add_enclave(intersection-enclave IntersectionEnclave isv_enclave ENCLAVE_UNTRUSTED_DIR)
add_enclave(hash-enclave HashingEnclave isv_enclave HASH_ENCLAVE_UNTRUSTED_DIR)

add_enclave(onesided-enclave onesided onesided ONESIDED_UNTRUSTED_DIR)
add_executable( onesided-app
    onesided-app/main.cpp onesided-app/networking.cpp onesided-app/radixsort.cpp ${ONESIDED_UNTRUSTED_DIR}/onesided_u.c ${HASH_ENCLAVE_UNTRUSTED_DIR}/isv_enclave_u.c
)

target_include_directories( onesided-app PRIVATE
    ${ONESIDED_UNTRUSTED_DIR}
    ${HASH_ENCLAVE_UNTRUSTED_DIR}
)

target_link_libraries( onesided-app
    util
) 


############################### libutil.a ###############################
add_library(util
    Util/LogBase.cpp
    Networking/Session.cpp Networking/Server.cpp
    Networking/Client.cpp
    Networking/AbstractNetworkOps.cpp
    Enclave_shared/IASReport.cpp
    Enclave_shared/UtilityFunctions.cpp
    Enclave_shared/Base64.cpp
    Enclave/Report.cpp
    Enclave/WebService.cpp
    Enclave/Enclave.cpp
)
target_include_directories( util PUBLIC
    Util Networking Enclave Enclave_shared
    dep/mbedtls/build/include
    ${SGX_SDK}/include
)
target_link_libraries(util LINK_PUBLIC 
    boost_system boost_thread
    ssl crypto
    log4cpp

    ${SGX_LIBRARY_PATH}/libsgx_ukey_exchange.a
    ${SGX_LIBS}
    proto
    pthread

    curl jsoncpp

    ${CMAKE_CURRENT_SOURCE_DIR}/dep/mbedtls/build/library/libmbedcrypto.a
    ${CMAKE_CURRENT_SOURCE_DIR}/dep/mbedtls/build/library/libmbedtls.a
    ${CMAKE_CURRENT_SOURCE_DIR}/dep/mbedtls-SGX/build/mbedtls_SGX-2.6.0/lib/libmbedtls_SGX_u.a
)

############################### app ###############################
add_executable( app
    Application/isv_app.cpp ${ENCLAVE_UNTRUSTED_DIR}/isv_enclave_u.c
    MessageHandler/MessageHandler.cpp MessageHandler/SessionHandler.cpp
)

target_include_directories( app PRIVATE
    ${ENCLAVE_UNTRUSTED_DIR}
    MessageHandler Application/isv_app
)

target_link_libraries( app
    util
) 

add_executable( repro 
    ServiceProvider/minimal_repro.cpp
)
target_link_libraries( repro
    util
)

add_executable( network_test
    Networking/NetworkingTest.cpp
)
target_link_libraries( network_test
    util
)

############################### service ###############################
add_executable( service
    ${HASH_ENCLAVE_UNTRUSTED_DIR}/isv_enclave_u.c
    ServiceProvider/isv_app/isv_app.cpp ServiceProvider/isv_app/VerificationManager.cpp
)
target_include_directories( service PRIVATE
    ${HASH_ENCLAVE_UNTRUSTED_DIR}
    ServiceProvider/sample_libcrypto
)
target_link_libraries( service 
    ${CMAKE_CURRENT_SOURCE_DIR}/ServiceProvider/sample_libcrypto/libsample_libcrypto.so
    util
    service_provider
)

############################### service_provider ###############################
add_library( service_provider SHARED
    ServiceProvider/service_provider/ecp.cpp Util/LogBase.cpp 
    ServiceProvider/service_provider/ias_ra.cpp Enclave_shared/UtilityFunctions.cpp
)
target_include_directories( service_provider PUBLIC
    WebService
    ServiceProvider/service_provider
)
target_include_directories( service_provider PRIVATE
    ServiceProvider/sample_libcrypto
    dep/mbedtls/build/include
)
target_link_libraries( service_provider
    util

    ${CMAKE_CURRENT_SOURCE_DIR}/ServiceProvider/sample_libcrypto/libsample_libcrypto.so
    ${CMAKE_CURRENT_SOURCE_DIR}/dep/mbedtls/build/library/libmbedcrypto.a
    ${CMAKE_CURRENT_SOURCE_DIR}/dep/mbedtls/build/library/libmbedtls.a
)
