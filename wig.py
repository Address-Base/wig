#!/usr/bin/env python3
u"""
wig - WebApp Information Gatherer

https://github.com/jekyc/wig

wig is a web application information gathering tool, which
can identify numerous Content Management Systems and other
administrative applications.

The application fingerprinting is based on checksums and
string matching of known files for different versions of
CMSes. This results in a score being calculated for each
detected CMS and its versions. Each detected CMS is
displayed along with the most probable version(s) of it.
The score calculation is based on weights and the amount of
"hits" for a given checksum.

wig also tries to guess the operating system on the server
based on the 'server' and 'x-powered-by' headers. A
database containing known header values for different
operating systems is included in wig, which allows wig to
guess Microsoft Windows versions and Linux distribution
and version.

"""


from __future__ import with_statement
from __future__ import absolute_import

# version specific Modules
# version specific Modules
import sys
import argparse
import time

from io import open

# version specific Modules
if sys.version_info.major == 3:

    import queue
    from classes.cache import Cache
    from classes.results import Results
    from classes.fingerprints import Fingerprints
    from classes.discovery import *
    from classes.headers import ExtractHeaders
    from classes.matcher import Match
    from classes.printer import Printer
    from classes.output import OutputPrinter
    from classes.output import OutputJSON
    from classes.request2 import Requester
    from classes.request2 import UnknownHostName


elif sys.version_info.major == 2:

    import Queue as queue
    from classes2.cache import Cache
    from classes2.results import Results
    from classes2.fingerprints import Fingerprints
    from classes2.discovery import *
    from classes2.headers import ExtractHeaders
    from classes2.matcher import Match
    from classes2.printer import Printer
    from classes2.output import OutputPrinter
    from classes2.output import OutputJSON
    from classes2.request2 import Requester
    from classes2.request2 import UnknownHostName



class Wig(object):
    def __init__(self, args):
        urls = None
        if args.input_file is not None:
            args.quiet = True

            with open(args.input_file, u'r') as input_file:
                urls = []
                for url in input_file.readlines():
                    url = url.strip()
                    urls.append(url if u'://' in url else u'http://'+url)

        elif u'://' not in args.url:
            args.url = u'http://' + args.url

        text_printer = Printer(args.verbosity)
        cache = Cache()
        cache.printer = text_printer

        self.options = {
            u'url': args.url.lower(),
            u'urls': urls,
            u'quiet': args.quiet,
            u'prefix': u'',
            u'user_agent': args.user_agent,
            u'proxy': args.proxy,
            u'verbosity': args.verbosity,
            u'threads': 10,
            u'batch_size': 20,
            u'run_all': args.run_all,
            u'match_all': args.match_all,
            u'stop_after': args.stop_after,
            u'no_cache_load': args.no_cache_load,
            u'no_cache_save': args.no_cache_save,
            u'write_file': args.output_file,
            u'subdomains': args.subdomains
        }

        self.data = {
            u'cache': cache,
            u'results': Results(self.options),
            u'fingerprints': Fingerprints(),
            u'matcher': Match(),
            u'printer': text_printer,
            u'detected_cms': set(),
            u'error_pages': set(),
            u'requested': queue.Queue()
        }

        if self.options[u'write_file'] is not None:
            self.json_outputter = OutputJSON(self.options, self.data)

        self.data[u'printer'].print_logo()

        self.results = None

    def scan_site(self):
        self.data[u'results'].printer = self.data[u'printer']
        self.data[u'requester'] = Requester(self.options, self.data)

        #
        # --- DETECT REDIRECTION ----------------
        #
        try:
            is_redirected, new_url = self.data[u'requester'].detect_redirect()
        except UnknownHostName as err:
            self.data[u'printer'].print_debug_line(err, 1)

            # fix for issue 8: https://github.com/jekyc/wig/issues/8
            # Terminate gracefully if the url is not
            # resolvable
            if self.options[u'write_file'] is not None:
                self.json_outputter.add_error(unicode(err))

            return


            if is_redirected:
                if not self.options[u'quiet']:
                    self.data[u'printer'].build_line(u"Redirected to ")
                    self.data[u'printer'].build_line(new_url, color=u'red')
                    self.data[u'printer'].print_built_line()

                    # raw_input was renamed in py3 from raw_input to input
                    if sys.version_info.major == 3:
                        choice = input(u"Continue? [Y|n]:")
                    elif sys.version_info.major == 2:
                        choice = raw_input(u"Continue?[Y|n]:")
                else:
                    choice = u'Y'

                # if not, exit
                if choice in [u'n', u'N']:
                    sys.exit(1)
                # else update the host
                else:
                    self.options[u'url'] = new_url
                    self.data[u'requester'].url = new_url

        #
        # --- PREP ------------------------------
        #
        msg = u'Scanning %s...' % (self.options[u'url'])
        self.data[u'printer'].print_debug_line(msg, 0, bold=True)

        # load cache if this is not disabled
        self.data[u'cache'].set_host(self.options[u'url'])
        if not self.options[u'no_cache_load']:
            self.data[u'cache'].load()

        # timer started after the user interaction
        self.data[u'timer'] = time.time()


        #
        # --- GET SITE INFO ---------------------
        #
        # get the title
        title = DiscoverTitle(self.options, self.data).run()
        self.data[u'results'].site_info[u'title'] = title

        # get the IP of the domain
        self.data[u'results'].site_info[u'ip'] = DiscoverIP(self.options[u'url']).run()


        #
        # --- DETECT ERROR PAGES ----------------
        #
        # find error pages
        self.data[u'error_pages'] = DiscoverErrorPage(self.options, self.data).run()

        # set matcher error pages
        self.data[u'matcher'].error_pages = self.data[u'error_pages']


        #
        # --- VERSION DETECTION -----------------
        #
        # Search for the first CMS
        DiscoverCMS(self.options, self.data).run()

        # find Platform
        DiscoverPlatform(self.options, self.data).run()

        #
        # --- GET MORE DATA FROM THE SITE -------
        #
        # find interesting files
        DiscoverInteresting(self.options, self.data).run()

        # find and request links to static files on the pages
        DiscoverMore(self.options, self.data).run()


        #
        # --- SEARCH FOR JAVASCRIPT LIBS --------
        #
        # do this after 'DiscoverMore' has been run, to detect JS libs
        # located in places not covered by the fingerprints
        DiscoverJavaScript(self.options, self.data).run()


        #
        # --- SEARCH THE CACHE ------------------
        #
        # some fingerprints do not have urls - search the cache
        # for matches
        DiscoverUrlLess(self.options, self.data).run()

        # search for cookies
        DiscoverCookies(self.data).run()

        # search the cache for headers
        ExtractHeaders(self.data).run()

        # search for indications of the used operating system
        DiscoverOS(self.options, self.data).run()

        # search for all CMS if specified by the user
        if self.options[u'match_all']:
            DiscoverAllCMS(self.data).run()

        # mark the end of the run
        self.data[u'results'].update()


        #
        # --- SEARCH FOR VULNERABILITIES --------
        #
        # search the vulnerability fingerprints for matches
        DiscoverVulnerabilities(self.data).run()


        #
        # --- SEARCH FOR TOOLS --------
        #
        DiscoverTools(self.data).run()

        #
        # --- SEARCH FOR SUBDOMAINS --------
        #
        if self.options[u'subdomains']:
            DiscoverSubdomains(self.options, self.data).run()


        #
        # --- SAVE THE CACHE --------------------
        #
        if not self.options[u'no_cache_save']:
            self.data[u'cache'].save()

        #
        # --- PRINT RESULTS ---------------------
        #
        # calc an set run time
        self.data[u'runtime'] = time.time() - self.data[u'timer']

        # update the URL count
        self.data[u'url_count'] = self.data[u'cache'].get_num_urls()

        # Create outputter and get results
        if self.options[u'write_file'] is not None:
            self.json_outputter.add_results()

        outputter = OutputPrinter(self.options, self.data)
        outputter.print_results()


    def get_results(self):
        return self.data[u'results'].results


    def reset(self):
        self.data[u'results'] = Results(self.options)
        self.data[u'cache'] = Cache()

    def run(self):
        if self.options[u'urls'] is not None:
            for url in self.options[u'urls']:
                self.reset()
                self.options[u'url'] = url.strip()
                self.scan_site()
        else:
            self.scan_site()

        if self.options[u'write_file'] is not None:
            self.json_outputter.write_file()


def parse_args(url=None):
    parser = argparse.ArgumentParser(description=u'WebApp Information Gatherer')

    parser.add_argument(u'url', nargs=u'?', type=str, default=None,
        help=u'The url to scan e.g. http://example.com')

    parser.add_argument(u'-l', type=str, default=None, dest=u"input_file",
        help=u'File with urls, one per line.')

    parser.add_argument(u'-q', action=u'store_true', dest=u'quiet', default=False,
        help=u'Set wig to not prompt for user input during run')

    parser.add_argument(u'-n', type=int, default=1, dest=u"stop_after",
        help=u'Stop after this amount of CMSs have been detected. Default: 1')

    parser.add_argument(u'-a', action=u'store_true', dest=u'run_all', default=False,
        help=u'Do not stop after the first CMS is detected')

    parser.add_argument(u'-m', action=u'store_true', dest=u'match_all', default=False,
        help=u'Try harder to find a match without making more requests')

    parser.add_argument(u'-u', action=u'store_true', dest=u'user_agent',
        default=u'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36',
        help=u'User-agent to use in the requests')

    parser.add_argument(u'-d', action=u'store_false', dest=u'subdomains', default=True,
        help=u'Disable the search for subdomains')

    parser.add_argument(u'-t', dest=u'threads', default=10, type=int,
        help=u'Number of threads to use')

    parser.add_argument(u'--no_cache_load', action=u'store_true', default=False,
        help=u'Do not load cached responses')

    parser.add_argument(u'--no_cache_save', action=u'store_true', default=False,
        help=u'Do not save the cache for later use')

    parser.add_argument(u'-N', action=u'store_true', dest=u'no_cache', default=False,
        help=u'Shortcut for --no_cache_load and --no_cache_save')

    parser.add_argument(u'--verbosity', u'-v', action=u'count', default=0,
        help=u'Increase verbosity. Use multiple times for more info')

    parser.add_argument(u'--proxy', dest=u'proxy', default=None,
        help=u'Tunnel through a proxy (format: localhost:8080)')

    parser.add_argument(u'-w', dest=u'output_file', default=None,
        help=u'File to dump results into (JSON)')

    args = parser.parse_args()

    if url is not None:
        args.url = url

    if args.input_file is None and args.url is None:
        raise Exception(u'No target(s) specified')

    if args.no_cache:
        args.no_cache_load = True
        args.no_cache_save = True

    return args



def wig(**kwargs):
    u"""
        Use this to call wig from python:

        >>>> from wig import wig
        >>>> w = wig(url='example.com')
        >>>> w.run()
        >>>> results = w.get_results()
    """

    # the url parameter must be supplied
    if u'url' not in kwargs:
        raise Exception(u'url parameter not supplied')
    args = parse_args(kwargs[u'url'])

    # set all other parameters supplied in the function call
    for setting in kwargs:
        if setting not in args:
            raise Exception(u'Unknown keyword supplied: %s' % (setting, ))
        setattr(args, setting, kwargs[setting])

    # need to be set in order to silence wig
    args.verbosity = -1
    args.quiet = True

    # return an instance of wig
    return Wig(args)



# if called from the command line
if __name__ == u'__main__':
    args = parse_args()

    try:
        wig = Wig(args)
        wig.run()
    except KeyboardInterrupt:
        raise
