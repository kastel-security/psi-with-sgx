# Private Set Intersection with SGX
This repository contains the source code for the Proof-of-Concept implementation of Private Set Intersection with Enclaves, without trusting fully in the security of the enclave.
The source code is part of a publication that will appear soon and we will update this repository once the publication is available.

The general structure of the code and interfacing with the SGX sdk was inspired by this sample application: https://github.com/svartkanin/linux-sgx-remoteattestation.
Additionally the code now contains xxhash (in Enclave_shared/xxhash.h, BSD 2-Clause) and a further optimized variant of radix sort based on https://github.com/AwardOfSky/Fast-Radix-Sort.

The code requires the installation of Intel SGX [here](https://github.com/01org/linux-sgx) and 
the SGX driver [here](https://github.com/01org/linux-sgx-driver). Furthermore, also a developer account
for the usage of IAS has be registered [Deverloper account](https://software.intel.com/en-us/sgx).
The spid and api_key need to be ented in ```GeneralSettings.h```


To compile the code:
 - clone https://github.com/ARMmbed/mbedtls.git into `dep/mbedtls` and build according to its instructions. We tested with commit `8266acacc8d6e1c65fba9a048f56339d0827b2fe`.
 - clone https://github.com/bl4ck5un/mbedtls-SGX into `dep/mbedtls-SGX` and build according to its instructions. We tested with commit `eab8e36a1e670a2fa66105735143eafa51931bff`.
 - install libjsoncpp-dev
 - create a `build` directory and execute cmake.
