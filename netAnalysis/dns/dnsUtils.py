#! /usr/bin/env python3
import argparse
import dns.resolver
import re
import sys
import time


class SPF:
    qualifiers = {"-": "Explicitly unauthorized host, if doesn't match rules.",
                  "?": "Neutral",
                  "~": "Unauthorized host, if doesn't match rules. (Debug)",
                  "+": "Authorized"
                  }

    mechanisms = {"a": "Address record (ipv4) Allowed: ",
                  "aaaa": "Address record (IPv6) allowed: ",
                  "all": "Previous rules matches.",
                  "exists": "Domain name resolves to any address? ",  # Mostly used in DNSBL.
                  "include": "References policies of: ",
                  "ip4": "IPv4 address(es) allowed: ",
                  "ip6": "IPv6 address(es) allowed: ",
                  "mx": "MX record allowed: ",
                  "ptr": "PTR record allowed: "  # Deprecated.
                  }

    def __init__(self, data):
        self.data = data
        if data[:5] == "v=spf":
            self.getSpfData()

    @staticmethod
    def _get_all_directive_info(allQua):
        """
        Prints the 'all directive' related information.
        :param allQua: qualifier of the all directive.
        :param allDir: directive.
        """
        status = "Pass"

        if allQua == "~":
            status = " be rejected and tagged."
        elif allQua == "-":
            status = " be rejected."
        elif allQua == "?":
            status = "... WTF? Neutral?"
        else:
            status = " be accepted."

        print("\t\033[1;31m[-]\033[0;0m If the previous rules doesn't match, the email will{}".format(status))

    def getDirectiveInfo(self, data):
        """
        Parses and prints SPF directive information that contains a qualifier (i.e [qualifier] mechanism).
        :param data: directive information.
        """
        qualifier = data[0]
        mechanism = data[1:].split(":")

        if not mechanism[0] == "all":
            print("\t\033[1;36m[+]\033[0;0m {0}{1}".format(self.mechanisms[mechanism[0]],
                                                           mechanism[1]))
            print("\t\033[1;35m[-]\033[0;0m Permission: {}\n".format(self.qualifiers[qualifier]))

        else:
            self._get_all_directive_info(qualifier)

    def getMechanismInfo(self, data):
        """
        Retreives SPF mechanism information.
        :param data: mechanism data.
        """
        m = data.partition(":")
        print("\t[*] {0}{1}".format(self.mechanisms[m[0]], m[2]))

    def getSpfData(self):
        """
        Gathers information of an SPF record.
        """
        directives = self.data.split()[1:]

        # Regexes
        q = "^(\?|\~|\-|\+)"
        m = "(ip(4|6):|include:|a:|aaaa:|all|mx|mx:|(exists|exists:)|(ptr:ptr))"
        directiveMatch = re.compile("{0}{1}".format(q, m))
        mechOnlyRegex = re.compile("(ip(4|6):)|(include:)|(mx:|mx)|(a{1,4}:|a{1,4})|exists:")
        modifierRegex = re.compile("redirect|exp")

        # Considered redundant.
        u = re.compile("mx/|a/")

        print("\n\033[1;36m[*]\033[0;0m Terms information")

        for directive in directives:
            modInx = re.match(modifierRegex, directive)
            if re.match(directiveMatch, directive):
                self.getDirectiveInfo(directive)

            elif re.match(mechOnlyRegex, directive):
                if not re.match(u, directive):
                    self.getMechanismInfo(directive)

            elif modInx:
                print("\t\033[1;32m[+]\033[0;0m {0} information: {1}".format(directive[:modInx.end()].title(),
                                                                             directive[modInx.end() + 1:]))
            else:
                print(directive)


class Resolver:
    rdclass = {1: "Internet",
               3: "CHAOS"
               }

    def __init__(self, domain, rdType, verbose):
        self.rdType = rdType
        self.domain = domain
        self.__verbose = verbose
        self.dnsQuery()

    def dnsQuery(self):
        try:
            dnsAns = dns.resolver.query(qname=self.domain, rdtype=self.rdType)
            self.chooseDnsQuery(dnsAns)

        except dns.resolver.NXDOMAIN as nxErr:
            print("\033[0;31mError: {}\033[0;0m".format(nxErr), file=sys.stderr)
            sys.exit(0)

        except Exception as genErr:
            print("\033[0;31mError: {}\033[0;0m".format(genErr), file=sys.stderr)
            sys.exit(0)

    def chooseDnsQuery(self, dnsData):
        ttl = dnsData.expiration - time.time()
        print("\033[1;32m[*]\033[0;0m Parsing DNS information from: {}".format(self.domain))
        print("\t[+] TTL: {} seconds \t Class: {}".format(int(ttl), self.rdclass[dnsData.rdclass]))

        if self.__verbose:
            print("\t\033[1;31m[!]\033[0;0m Expiration date: ", time.ctime(dnsData.expiration))

        if dnsData.rdtype == 16:
            self.parseTxt(dnsData)

        elif dnsData.rdtype == 2:
            self.parseNS(dnsData)

        elif dnsData.rdtype == 15:
            self.parseMX(dnsData)

        elif dnsData.rdtype == 6:
            self.parseSOA(dnsData)

        else:
            for data in dnsData:
                print("\t[+] {0} record: {1}".format(self.rdType, data))

    def parseTxt(self, txtData):
        print("\033[1;32m[*]\033[0;0m {} TXT raw data ".format(self.domain))
        for data in txtData:
            print(data)

        if self.__verbose:
            print("\n\033[1;32m[*]\033[0;0m {} verbose TXT information.".format(self.domain))
            for d in txtData:
                data = d.to_text().strip("\"\"")

                if data[:5] == "v=spf":
                    print("\033[1;32m[*]\033[0;0m SPF Data.")
                    print("\t\033[1;32m[-]\033[0;0m SPF version: ", data[5])
                    SPF(data)
                else:
                    print("\n\033[1;31m[!]\033[0;0m Additional information: {}".format(data))

    @staticmethod
    def parseNS(nsData):
        for data in nsData:
            print("\033[1;34m[*]\033[0;0m Name server: ", data)

    @staticmethod
    def parseMX(self, mxData):
        for data in mxData:
            print("\033[1;32m[*]\033[0;0m MX server: ", data)

    @staticmethod
    def parseSOA(self, soaData):
        print("\n\033[1;34m[*]\033[0;0m SOA information.")

        for data in soaData:
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
