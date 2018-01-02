#! /usr/bin/env python3
import argparse
import dns.resolver
import re
import sys
import time


class SPF:
    qualifiers = {"-": "Explicitly unauthorized host.",
                  "?": "Unknown authorization.",
                  "~": "Unauthorized host, if doesn't match rules. (Debug)",
                  "+": "Authorized"
                  }
    mechanisms = {"a": "Address record can resolve the sender address (ipv4)? ",
                  "aaaa": "Address record can resolve the sender address (ipv6)? ",
                  "mx": "MX record can resolve sender address? ",
                  "ptr": "Client address has to a DNS and this can resolve client address? ",  # Deprecated.
                  "exists": "Domain name resolves to any address? "  # Mostly used in DNSBL.
                  }

    def __init__(self, data):
        self.data = data
        if data[:5] == "v=spf":
            self.get_spf_data()

    @staticmethod
    def _get_all_directive_info(value):
        ret = None
        if value[0] == "~":
            ret = "If previous rules doesn't match, message will be rejected with debug info."

        elif value[0] == "-":
            ret = "If previous rules doesn't match, message will be rejected."

        elif value[0] == "?":
            ret = "No policy."

        elif value[0] == "+" or value[0] == "a":
            ret = "If previous rules match, message wil be sent."

        return ret

    def _get_mechanism_info(self, m, q=""):
        if (q == "") or (q == "+"):
            return "{0}{1}".format(self.mechanisms[m], self.qualifiers["+"])

        return "{0}{1}".format(self.mechanisms[m], self.qualifiers[q])

    def _parse_directive_info(self, directives):

        for value in directives:
            if value in self.mechanisms:
                print("\t\t\033[1;36m[-]\033[0;0m {}".format(self._get_mechanism_info(value)))

            elif value[0] in self.qualifiers.keys():
                if value[1:] in self.mechanisms:
                    print("\t\t\033[1;36m[-]\033[0;0m {}".format(self._get_mechanism_info(value[1:], value[0])))

                if "all" == value[1:]:
                    print("\t\t\033[1;36m[-]\033[0;0m {}".format(self._get_all_directive_info(value)))

    def get_directive_info(self, directives):
        if len(directives) == 0:
            return False

        print("\t\033[1;36m[+]\033[0;0m Directive information")
        self._parse_directive_info(directives)

    def get_spf_data(self):
        spf_data = self.data.split()
        inx = 1
        directives = list()

        qualifier_regex = "\+|\-|\?|\~"
        mechanism_regex = "all|include|a|mx|ptr|ip4|ip6|exists"
        directive_regex = re.compile("({0})|({1})$".format(qualifier_regex, mechanism_regex))
        modifiers_regex = re.compile("exp|redirect")

        print("\t\033[1;32m[*]\033[0;0m SPF version: {}".format(spf_data[0][5]))

        for value in spf_data:
            modifier_inx = re.match(modifiers_regex, value)

            if value[:8] == "include:":
                print("\t\033[1;34m[+]\033[0;0m Policy refers to domain No.{0}: {1}".format(inx,
                                                                                            value[8:]))
                inx += 1

            if (value[:4] == "ip4:") or (value[:4] == "ip6"):
                print("\t\033[1;32m[+]\033[0;0m Allowed IP(s) to send emails to given domain: {}".format(value[4:]))

            if value[:3] == "mx:":
                print("\t\033[1;34m[+]\033[0;0m Allowed server to send emails to given domain: {}".format(value[3:]))

            if re.match(directive_regex, value):
                directives.append(value)

            if modifier_inx:
                mod_name = value[0: modifier_inx.end()]
                mod_info = value[modifier_inx.end() + 1:]
                print("\t[*] {0} information: {1}".format(mod_name.title(), mod_info))

        self.get_directive_info(directives)


class Resolver:
    rdclass = {1: "Internet",
               3: "CHAOS"
               }

    def __init__(self, domain, rd_type, verbose):
        self.rd_type = rd_type
        self.domain = domain
        self.__verbose = verbose
        self.dns_query()

    def dns_query(self):
        try:
            dns_ans = dns.resolver.query(qname=self.domain, rdtype=self.rd_type)
            self.choose_dns_query(dns_ans)

        except dns.resolver.NXDOMAIN as nxErr:
            print("\033[0;31mError: {}\033[0;0m".format(nxErr), file=sys.stderr)
            sys.exit(0)

        except Exception as genErr:
            print("\033[0;31mError: {}\033[0;0m".format(genErr), file=sys.stderr)
            sys.exit(0)

    def choose_dns_query(self, dns_data):
        ttl = dns_data.expiration - time.time()
        print("\033[1;32m[*]\033[0;0m Parsing DNS information from: {}".format(self.domain))
        print("\t[+] TTL: {} seconds \t Class: {}".format(int(ttl), self.rdclass[dns_data.rdclass]))

        if self.__verbose:
            print("\t\033[1;31m[!]\033[0;0m Expiration date: ", time.ctime(dns_data.expiration))

        if dns_data.rdtype == 16:
            self.parse_txt(dns_data)

        elif dns_data.rdtype == 2:
            self.parse_ns(dns_data)

        elif dns_data.rdtype == 15:
            self.parse_mx(dns_data)

        elif dns_data.rdtype == 6:
            self.parse_soa(dns_data)

        else:
            for data in dns_data:
                print("\t[+] {0} record: {1}".format(self.rd_type, data))

    def parse_txt(self, txt_data):
        print("\033[1;32m[*]\033[0;0m {} TXT raw data ".format(self.domain))
        for data in txt_data:
            print(data)

        if self.__verbose:
            print("\n\033[1;32m[*]\033[0;0m {} verbose TXT information.".format(self.domain))
            for d in txt_data:
                data = d.to_text().strip("\"\"")

                if data[:5] == "v=spf":
                    SPF(data)
                else:
                    print("\n\033[1;31m[!]\033[0;0m Additional information: {}".format(data))

    @staticmethod
    def parse_ns(ns_data):
        for data in ns_data:
            print("\033[1;34m[*]\033[0;0m Name server: ", data)

    @staticmethod
    def parse_mx(self, mx_data):
        for data in mx_data:
            print("\033[1;32m[*]\033[0;0m MX server: ", data)

    @staticmethod
    def parse_soa(self, soa_data):
        print("\n\033[1;34m[*]\033[0;0m SOA information.")

        for data in soa_data:
            print("\t\033[1;34m[+]\033[0;0m Primary master name server: ", data.mname)
            print("\t\033[1;34m[+]\033[0;0m Admin email address: ", data.rname)
            print("\t\033[1;34m[+]\033[0;0m Serial: ", data.serial)
            print("\t\033[1;34m[+]\033[0;0m Detect zone changes at {}s ".format(data.refresh))
            print("\t\033[1;34m[+]\033[0;0m Retry SN request at {}s".format(data.retry))
            print("\t\033[1;34m[+]\033[0;0m Stop answering requests at {}s".format(data.expire))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS utilities.")
    parser.add_argument("domain", help="Domain to query")

    parser.add_argument("-t", "--type", action="store", dest="rd_type", default="NS",
                        help="Domain query type (Default NS).")

    parser.add_argument("-v", "--verbose", action="store_true",
                        dest="verbose", default=False,
                        help="Print verbose information (Default False)")

    args = parser.parse_args()
    Resolver(args.domain, args.rd_type, args.verbose)
