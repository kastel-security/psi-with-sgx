#ifndef GENERALSETTINGS_H
#define GENERALSETTINGS_H

#include <string>

using namespace std;

namespace Settings {
	static int rh_port = 22222;
	static string rh_host = "localhost";
        static string server_crt = "server.crt"; //certificate for the HTTPS connection between the SP and the App
	static string server_key = "server.key";

	static string spid = "... your SPID here ..."; //SPID provided by Intel after registration for the IAS service
	static string api_key = ".... your api key here ..."; //API key provided by Intel after registration for the IAS service
	static string ias_url = "https://api.trustedservices.intel.com/sgx/dev/attestation/v3/";
	static bool curl_verbose = false;
}

#endif
