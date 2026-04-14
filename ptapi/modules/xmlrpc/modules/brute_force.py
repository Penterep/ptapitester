"""XML-RPC Brute Force test — tests login methods with wordlists"""
import xmlrpc.client
from ptlibs.ptprinthelper import ptprint
__TESTLABEL__ = "XML-RPC Brute Force test"

class BruteForce:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.helpers.print_header(__TESTLABEL__)

    def run(self):
        auth_patterns = ["login", "auth", "authenticate", "wp.getUsersBlogs",
                         "wp.getProfile", "user.login", "user.authenticate"]
        auth_methods = [m for m in self.helpers.discovered_methods
                        if any(p.lower() in m.lower() for p in auth_patterns)]

        if not auth_methods:
            ptprint("No authentication methods found. Skipping.", "INFO",
                    not self.args.json, indent=4)
            return

        ptprint(f"Testing brute force on: {', '.join(auth_methods)}", "INFO",
                not self.args.json, indent=4)

        server = self.helpers.get_xmlrpc_proxy()
        passwords = self.helpers.load_wordlist("passwords.txt")
        if not passwords:
            passwords = ["123456", "password", "admin", "admin123", "root",
                         "test", "letmein", "welcome", "monkey", "dragon"]
        usernames = self.helpers.load_wordlist("usernames.txt")
        if not usernames:
            usernames = ["admin", "root", "user", "test", "administrator"]

        attempts = 0
        for auth_method in auth_methods:
            for user in usernames:
                for pwd in passwords:
                    attempts += 1
                    try:
                        result = getattr(server, auth_method)(user, pwd)

                        # Check various success patterns
                        is_success = False

                        # Dict with status: ok
                        if isinstance(result, dict) and result.get("status") == "ok":
                            is_success = True
                        # Dict without error key
                        elif isinstance(result, dict) and "error" not in result and "reason" not in result:
                            is_success = True
                        # Non-empty list (e.g. wp.getUsersBlogs)
                        elif isinstance(result, list) and len(result) > 0:
                            is_success = True
                        # Boolean true
                        elif result is True:
                            is_success = True
                        # Non-empty string without error indicators
                        elif isinstance(result, str) and result and "error" not in result.lower() and "fail" not in result.lower():
                            is_success = True

                        if is_success:
                            ptprint(f"Valid credentials found: {user}:{pwd} via {auth_method}", "VULN",
                                    not self.args.json, indent=4, colortext=True)
                            self.ptjsonlib.add_vulnerability(
                                "PTV-RPC-BRUTEFORCE-SUCCESS", node_key=self.helpers.node_key,
                                data={"evidence": f"Method: {auth_method}, Credentials: {user}:{pwd}"})
                            return

                    except xmlrpc.client.Fault:
                        pass
                    except Exception:
                        pass

        ptprint(f"Brute force completed ({attempts} attempts), no valid credentials.",
                "INFO", not self.args.json, indent=4)

def run(args, ptjsonlib, helpers, http_client, common_tests):
    BruteForce(args, ptjsonlib, helpers, http_client, common_tests).run()
