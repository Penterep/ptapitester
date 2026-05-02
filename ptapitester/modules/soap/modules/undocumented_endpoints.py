"""
SOAP Undocumented Endpoints discovery

Dictionary attack on endpoint paths to find additional SOAP endpoints
not declared in WSDL. Uses dual-baseline approach to reduce false positives.

Discovered endpoints are added to helpers.discovered_endpoints so that
subsequent endpoint-level tests can iterate over all found endpoints.
"""
from urllib.parse import urlparse
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "SOAP Undocumented Endpoints discovery"


class UndocumentedEndpoints:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.helpers.print_header(__TESTLABEL__)

    def run(self):
        wordlist = self.helpers.load_wordlist("soap_endpoints.txt")
        if not wordlist:
            ptprint("Endpoint wordlist not available. Skipping.", "INFO",
                    not self.args.json, indent=4)
            return

        soap_probe = (
            '<?xml version="1.0"?>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soapenv:Body><probe>baseline_test</probe></soapenv:Body>'
            '</soapenv:Envelope>'
        )

        baseline1_path = "/__nonexistent_path_xyz_123__"
        baseline2_path = "/__another_fake_endpoint_abc__"

        b1 = self.helpers.send_soap_request(
            url=self.helpers.base_url + baseline1_path, data=soap_probe)
        b2 = self.helpers.send_soap_request(
            url=self.helpers.base_url + baseline2_path, data=soap_probe)

        if b1 is None or b2 is None:
            ptprint("Could not establish baseline. Skipping.", "INFO",
                    not self.args.json, indent=4)
            return

        if b1.status_code == 200 and b2.status_code == 200 and \
           abs(len(b1.text) - len(b2.text)) < 100:
            ptprint("Server has catch-all endpoint. Dictionary attack unreliable.",
                    "INFO", not self.args.json, indent=4)
            return

        baseline_status = b1.status_code
        baseline_len_1 = len(b1.text)
        baseline_len_2 = len(b2.text)
        tolerance = abs(baseline_len_1 - baseline_len_2) + 30

        main_path = urlparse(self.helpers.endpoint_url).path.rstrip('/')
        found = []

        for path in wordlist:
            if not path.startswith('/'):
                path = '/' + path
            if path == main_path:
                continue

            test_url = self.helpers.base_url + path
            r = self.helpers.send_soap_request(url=test_url, data=soap_probe)
            if r is None:
                continue

            is_different = False
            if r.status_code != baseline_status:
                is_different = True
            elif abs(len(r.text) - baseline_len_1) > tolerance:
                is_different = True

            if is_different and r.status_code in (200, 301, 302, 401, 403, 500):
                found.append({"path": path, "url": test_url, "status": r.status_code})
                ptprint(f"  Undocumented endpoint found: {path} (HTTP {r.status_code})",
                        "VULN", not self.args.json, indent=4, colortext=True)

                self.helpers.add_endpoint(test_url)

        if found:
            evidence = (f"Dictionary attack found {len(found)} endpoint(s) not in WSDL: " +
                        ", ".join(f["path"] for f in found))
            self.ptjsonlib.add_vulnerability(
                "PTV-SOAP-UNDOCUMENTED-ENDPOINTS",
                node_key=self.helpers.node_key,
                data={"evidence": evidence})
        else:
            ptprint("No undocumented endpoints found.", "OK",
                    not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    UndocumentedEndpoints(args, ptjsonlib, helpers, http_client, common_tests).run()
