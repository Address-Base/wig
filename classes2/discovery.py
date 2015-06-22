u"""
Collection of classes to extract information from the site.

"""

from __future__ import with_statement
from __future__ import absolute_import
import re
import socket
import requests
from urlparse import urlparse
from collections import Counter, defaultdict
from HTMLParser import HTMLParser
from itertools import imap

class DiscoverAllCMS(object):
    u"""
    Match all fingerprints against all responses
    this might generate false positives
    """
    def __init__(self, data):
        self.cache = data[u'cache']
        self.results = data[u'results']
        self.matcher = data[u'matcher']
        self.fps = data[u'fingerprints']
        self.printer = data[u'printer']

        # only used for pretty printing of debugging info
        self.tmp_set = set()

    def run(self):
        self.printer.print_debug_line(u'Checking for more matches in cache (option -a)  ...', 1)

        # find matches for all the responses in the cache
        for fp_category in [u'cms', u'platform']:
            for fp_type in self.fps.data[fp_category]:
                fps = self.fps.data[fp_category][fp_type][u'fps']

                for response in self.cache.get_responses():
                    matches = self.matcher.get_result(fps, response)
                    for fp in matches:
                        self.results.add(fp_category, fp[u'name'], fp[u'output'], fp)

                        if (fp[u'name'], fp[u'output']) not in self.tmp_set:
                            self.printer.print_debug_line(u'- Found match: %s %s' % (fp[u'name'], fp[u'output']), 2)

                        self.tmp_set.add((fp[u'name'], fp[u'output']))


class DiscoverCMS(object):
    u"""
    Search for the CMS and its version.

    It searches for a CMS match by splitting the fingerprints
    into batches of the given size (options['batch_size']).
    One a batch of fingerprints urls have been requested, the
    responses are checked for CMS matches. If a match is found,
    all the URLs for that CMS are requested in order to determine
    the version. If options['run_all'] is set, this continues until
    all fingerprints are checked (this is not the default).

    """
    def __init__(self, options, data):
        self.printer = data[u'printer']
        self.matcher = data[u'matcher']
        self.requester = data[u'requester']
        self.result = data[u'results']
        self.printer = data[u'printer']

        self.batch_size = options[u'batch_size']
        self.num_cms_to_find = options[u'stop_after']
        self.find_all_cms = options[u'run_all']

        # only used for pretty printing of debugging info
        self.tmp_set = set()

        self.queue = defaultdict(list)
        for fp_type in data[u'fingerprints'].data[u'cms']:
            for fp in data[u'fingerprints'].data[u'cms'][fp_type][u'fps']:
                self.queue[fp[u'url']].append(fp)


    def get_queue(self, cms=None):
        queue = []
        if cms is None:
            for _ in xrange(self.batch_size):
                try:
                    url, fp_list = self.queue.popitem()
                    queue.append(fp_list)
                except KeyError:
                    break
        else:
            # the following procedure is *not* optimal
            # the self.queue dict is completely destroyed and
            # and rebuilt each time this procedure is called :(

            # create a temp queue dict
            tmp_queue = defaultdict(list)

            # remove elements from the dict until it is empty
            while len(self.queue) > 0:
                url, fp_list = self.queue.popitem()

                # remove all the elements of a queue entry's list
                # one-by-one and check if the fingerprints are
                # belong to the specified 'cms'
                tmp_list, out_list = [], []

                while len(fp_list) > 0:
                    # remove the fingerprint
                    fp = fp_list.pop()

                    # if the fingerprint matches the cms, add it to the
                    # out_list for the current url
                    # otherwise add it to the tmp_list
                    if fp[u'name'] == cms:
                        out_list.append(fp)
                    else:
                        tmp_list.append(fp)

                # if there are elements in tmp_list (the new list of fps that
                # that do *not* match the 'cms'), add it to the tmp_queue's entry
                # for the current url
                if len(tmp_list) > 0:
                    tmp_queue[url].extend(tmp_list)

                # if matches for the specified cms have been found, add the list
                # to the fingerprintQueue for the requester
                if len(out_list) > 0:
                    queue.append(out_list)

            # replace the queue with the tmp queue
            self.queue = tmp_queue

        return queue


    def run(self):
        batch_no = 0
        self.printer.print_debug_line(u'Determining CMS type ...', 1)

        detected_cms = []
        stop_searching = len(detected_cms) >= self.num_cms_to_find

        while (not stop_searching or self.find_all_cms) and (not len(self.queue) == 0):
            self.printer.print_debug_line(u'Checking fingerprint group no. %s ...' % (batch_no, ), 3)

            # set the requester queue
            results = self.requester.run(u'CMS', self.get_queue())

            # search for CMS matches
            cms_matches = []
            while not results.empty():
                fingerprints, response = results.get()

                for fp in self.matcher.get_result(fingerprints, response):
                    self.result.add(u'cms', fp[u'name'], fp[u'output'], fp)
                    cms_matches.append(fp[u'name'])

            # search for the found CMS versions
            for cms in cms_matches:

                # skip checking the cms, if it has already been detected
                if cms in detected_cms: continue

                if cms not in self.tmp_set:
                    self.tmp_set.add(cms)
                    self.printer.print_debug_line(u'- Found CMS match: %s' % (cms, ), 2)

                # set the requester queue with only fingerprints for the cms
                results = self.requester.run(u'CMS_version', self.get_queue(cms))

                # find the results
                self.printer.print_debug_line(u'Determining CMS version ...', 1)
                while results.qsize() > 0:
                    res_fps, response = results.get()
                    for fp in self.matcher.get_result(res_fps, response):
                        self.result.add(u'cms', fp[u'name'], fp[u'output'], fp)

                        if (fp[u'name'], fp[u'output']) not in self.tmp_set:
                            self.tmp_set.add((fp[u'name'], fp[u'output']))
                            self.printer.print_debug_line(u'- Found version: %s %s' % (fp[u'name'], fp[u'output']), 2)

                # update the stop criteria
                detected_cms.append(cms)

            stop_searching = (len(detected_cms) >= self.num_cms_to_find) or len(self.queue) == 0
            batch_no += 1



class DiscoverCookies(object):
    u"""
    Check if the site sets any cookies.

    It checks the results in the cache, and therefore
    it should be run last.
    """
    def __init__(self, data):
        self.data = data
        self.printer = data[u'printer']

    def run(self):
        self.printer.print_debug_line(u'Checking for cookies ...', 1)

        cookies = set()
        for r in self.data[u'cache'].get_responses():
            try:
                c = r.headers[u'set-cookie'].strip().split(u'=')[0]
                if c not in cookies:
                    self.printer.print_debug_line(u'- Found cookie: %s' % (c, ), 2)

                cookies.add(c)

            except:
                pass

        self.data[u'results'].site_info[u'cookies'] = cookies


class DiscoverSubdomains(object):
    u"""
    Search for sub-domains.

    The current implementation does not wig's requester class
    which means that proxy, threads, user-agent, etc are not
    used. This should implemented, but it should be ensured
    that the cache is not used, as this might impact the results
    of the version detection.
    """

    def __init__(self, options, data):
        self.data = data
        self.options = options

        self.results = data[u'results']
        self.subdomains = data[u'fingerprints'].data[u'subdomains'][u'fps']
        self.url = options[u'url']
        self.printer = data[u'printer']

        self.domain = urlparse(self.url).netloc
        self.domain = u'.'.join(self.domain.split(u':')[0].split(u'.')[-2:])

        self.random_domain = u'random98f092f0b7'
        self.scheme_sets = set([(u'http', u'80'),(u'https', u'443')])

    def check_subdomain(self, subdomain, scheme, port):
        domain = subdomain + u'.' + self.domain

        try:
            # lookup the IP of the domain
            ip = socket.gethostbyname(domain)

            # try to get the title of the site hosted on the domain
            try:
                req = requests.get(url=scheme + u'://' + domain, timeout=1)
                data = req.content.decode(u'utf-8')
                title = re.findall(ur'<title>\s*(.*)\s*</title>', data)[0].strip()
                if len(title) > 50:
                    title =  title[:47] + u' ...'

                result = (scheme + u'://' + domain + u":" + port, title, ip)

            except:
                result = None
        except:
            result = None

        return result

    def run(self):
        self.printer.print_debug_line(u'Searching for sub domains ...', 1)

        # check if the site accepts all sub-domains
        control_set = set()
        for scheme, port in self.scheme_sets:
            domain_test = self.check_subdomain(self.random_domain, scheme, port)
            if domain_test:
                control_set.add((domain_test[1], domain_test[2]))

        # check all sub domains
        for subdomain in self.subdomains:
            for scheme, port in self.scheme_sets:
                result = self.check_subdomain(subdomain, scheme, port)
                if result:
                    # compare the current results to the control
                    if not (result[1], result[2]) in control_set:
                        self.results.add_subdomain(*result)


class DiscoverErrorPage(object):
    u"""
    Find error pages on the site.

    The requester has a built-in list of items and patterns
    to remove before calculating a checksum of pages that
    should not exists
    """
    def __init__(self, options, data):
        self.host = options[u'url']
        self.fps = data[u'fingerprints'].data[u'error_pages'][u'fps']
        self.requester = data[u'requester']
        self.printer = data[u'printer']


    def run(self):
        self.requester.find_404s = True

        self.printer.print_debug_line(u'Error page detection ...', 1)

        queue = [[fp] for fp in self.fps]
        results = self.requester.run(u'ErrorPages', queue)

        error_pages = set()
        while results.qsize() > 0:
            fp, response = results.get()
            if response is not None:
                error_pages.add(response.md5_404)
                error_pages.add(response.md5_404_text)
                error_tuple = (response.md5_404, response.md5_404_text, fp[0][u'url'])
                self.printer.print_debug_line(u'- Error page fingerprint: %s, %s - %s' % error_tuple, 2)

        self.requester.find_404s = False

        return error_pages


class DiscoverInteresting(object):
    u"""
    Search for commonly interesting files and folders
    """

    def __init__(self, options, data):
        self.url = options[u'url']
        self.printer = data[u'printer']
        self.requester = data[u'requester']
        self.matcher = data[u'matcher']
        self.result = data[u'results']
        self.error_pages = data[u'error_pages']
        self.cache = data[u'cache']
        self.category = u"interesting"

        # add the fingerprints to the queue, ensuring that
        # all fps with the same url, are collected in a list
        self.queue = defaultdict(list)
        for fp in data[u'fingerprints'].data[u'interesting'][u'fps']:
            self.queue[fp[u'url']].append(fp)


    def run(self):
        self.printer.print_debug_line(u'Detecting interesting files ...', 1)

        # process the results
        results = self.requester.run(u'Interesting', list(self.queue.values()))

        while results.qsize() > 0:
            fps, response = results.get()

            # if the response includes a 404 md5, check if the response
            # is a redirection to a known error page
            # this is a fix for https://github.com/jekyc/wig/issues/7
            if response is not None:
                redirected = response.md5_404 in self.error_pages
                redirected = redirected or (response.md5_404_text in self.error_pages)
                redirected = redirected or (response.md5_404_text == self.cache[self.url].md5_404_text)

                # if it is an error page, skip it
                if redirected: continue

            # if the response does not have a 404 md5, something most have gone wrong
            # skip checking the page
            else:
                continue

            for fp in self.matcher.get_result(fps, response):
                self.result.add(self.category, None, None, fp, weight=1)
                try:
                    self.printer.print_debug_line(u'- Found file: %s (%s)' % (fp[u'url'], fp[u'note']), 2)
                except:
                    pass



class DiscoverIP(object):
    u"""
    Get the IP address of the host
    """

    def __init__(self, path):
        self.path = path

    def run(self):
        try:
            hostname = self.path.split(u'//')[1]
            hostname = hostname.split(u'/')[0]
            ip = socket.gethostbyname(hostname)
        except Exception, e:
            #print(e)
            ip = u'Unknown'

        return ip



class DiscoverJavaScript(object):
    u"""
    Search for JavaScript
    """

    def __init__(self, options, data):
        self.printer = data[u'printer']
        self.cache = data[u'cache']
        self.matcher = data[u'matcher']
        self.result = data[u'results']

        self.fingerprints = []
        for fp_type in data[u'fingerprints'].data[u'js']:
            self.fingerprints.extend(data[u'fingerprints'].data[u'js'][fp_type][u'fps'])


    def run(self):
        self.printer.print_debug_line(u'Detecting Javascript ...', 1)
        for response in self.cache.get_responses():

            # match only if the response is JavaScript
            #  check content type
            content_type = response.headers[u'content-type'] if u'content-type' in response.headers else u''
            # and extension
            is_js = u'javascript' in content_type or u'.js' in response.url.split(u'.')[-1]

            # if the response is JavaScript try to match it to the known fingerprints
            if is_js:
                matches = self.matcher.get_result(self.fingerprints, response)
                for fp in matches:
                    self.result.add(u'js', fp[u'name'], fp[u'output'], fingerprint=fp, weight=1)
                    self.printer.print_debug_line(u'- Found JavaScript: %s %s' % (fp[u'name'], fp[u'output']), 2)



# Used by the DiscoverMore crawler
class LinkExtractor(HTMLParser):
    u"""
    Helper class that extracts linked ressources

    Only checks for img, script, and link tags
    """

    def __init__(self, strict):
        HTMLParser.__init__(self)
        self.strict = strict
        self.results = set()

    def get_results(self):
        return self.results

    def handle_starttag(self, tag, attrs):
        try:
            if tag == u'script' or tag == u'img':
                for attr in attrs:
                    if attr[0] == u'src':
                        self.results.add(attr[1])
            if tag == u'link':
                for attr in attrs:
                    if attr[0] == u'href':
                        self.results.add(attr[1])
        except:
            pass



class DiscoverMore(object):
    u"""
    Crawls host to discover more items

    This searches to responses for more items to test.
    This could help detect CMS and version if the default
    paths have been changed. However, it does increase the
    amount of requests send to host
    """

    def __init__(self, options, data):
        self.host = options[u'url']
        self.threads = options[u'threads']
        self.printer = data[u'printer']
        self.cache = data[u'cache']
        self.result = data[u'results']
        self.matcher = data[u'matcher']
        self.requester = data[u'requester']
        self.fingerprints = data[u'fingerprints']


    def _get_urls(self, response):
        # only get urls from elements that use 'src' to avoid
        # fetching resources provided by <a>-tags, as this could
        # lead to the crawling of the whole application
        regexes = [u'src="(.+?)"', u"src='(.+?)'"]

        urls = set()
        for regex in regexes:
            for match in re.findall(regex, response.body):
                urls.add(match)

        return urls


    def run(self):
        self.printer.print_debug_line(u'Detecting links ...', 1)
        resources = set()
        parser = LinkExtractor(strict=False)

        for req in self.cache.get_responses():
            # skip pages that do not set 'content-type'
            # these might be binaries
            if not u'content-type' in req.headers:
                continue

            # skip responses that have been discovered
            # with 'DiscoverMore'
            if req.crawled_response:
                continue

            # only scrape pages that can contain links/references
            if u'text/html' in req.headers[u'content-type']:
                tmp = self._get_urls(req)
                parser.feed(req.body)
                tmp = tmp.union(parser.get_results())

                for i in tmp:
                    url_data = urlparse(i)

                    # skip data urls
                    if url_data.path.startswith(u'data:'): continue

                    resources.add(i)

        # the items in the resource set should mimic a list of fingerprints:
        # a fingerprint is a dict with at least an URL key
        self.printer.print_debug_line(u'- Discovered %s new resources' % (len(resources), ), 2)

        # prepare the urls
        queue = defaultdict(list)
        for url in resources:
            queue[url].append({u'url': url})

        # fetch'em
        results = self.requester.run(u'DiscoverMore', list(queue.values()))


class DiscoverOS(object):
    u"""
    Try to determine the OS used on the host

    Often Linux/GNU web servers send software package name and version
    in the HTTP header 'server'. These are compared to a database of
    Linux/GNU distributions and their versions.

    ASP.NET is also matched.
    """

    def __init__(self, options, data):
        self.printer = data[u'printer']
        self.cache = data[u'cache']
        self.results = data[u'results']
        self.fingerprints = data[u'fingerprints'].data[u'os'][u'fps']

        self.os = Counter()
        self.os_family_list = Counter()
        self.matched_packages = set()


    def search_and_prioritize_os(self, pkg_name, pkg_version):
        for fp in self.fingerprints:
            if fp[u'pkg_name'] == pkg_name and fp[u'pkg_version'] == pkg_version:
                weight = 1 if not u'weight' in fp else fp[u'weight']

                if not type(fp[u'os_version']) == type([]):
                    fp[u'os_version'] = [fp[u'os_version']]

                for os_version in fp[u'os_version']:
                    if fp[u'os_name'].lower() in self.os_family_list:
                        self.printer.print_debug_line(u'- Prioritizing fingerprints for OS: %s' % (fp[u'os_name'], ), 7)
                        self.os[(fp[u'os_name'], os_version)] += weight * 100
                    else:
                        self.os[(fp[u'os_name'], os_version)] += weight


    def find_match_in_headers(self, response):
        headers = response.headers
        if u'server' in headers:
            line = headers[u'server']

            if u"(" in line:
                os = line[line.find(u'(')+1:line.find(u')')]

                # hack for RHEL
                if os == u'Red Hat':
                    os = u'Red Hat Enterprise Linux'

                line = line[:line.find(u'(')-1] + line[line.find(u')')+1: ]
            else:
                os = None

            if os is not None:
                self.os_family_list[os.lower()] += 1

            for part in line.split(u" "):
                try:
                    pkg, version = list(imap(unicode.lower, part.split(u'/')))
                    self.search_and_prioritize_os(pkg, version)

                except Exception, e:
                    continue


    def find_match_in_results(self):
        platforms = self.results.scores[u'platform']
        for pkg in platforms:
            for version in platforms[pkg]:
                # hack for asp.net
                if pkg == u'ASP.NET':
                    version = version[:3] if not version.startswith(u"4.5") else version[:5]

                self.search_and_prioritize_os(pkg, version)


    def finalize(self):
        # add OS to results: self.os: {(os, version): weight, ...}
        results = []
        for p in self.os:
            results.append({u'version': p[1], u'os': p[0], u'count': self.os[p]})

        if len(results) == 0: return

        prio = sorted(results, key=lambda x: x[u'count'], reverse=True)
        max_count = prio[0][u'count']
        for i in prio:
            if i[u'count'] == max_count:
                self.results.add(u'os', i[u'os'], i[u'version'], weight=i[u'count'])
                self.printer.print_debug_line(u'- Found OS: %s %s' % (i[u'os'], i[u'version']), 2)
            else:
                break


    def run(self):
        self.printer.print_debug_line(u'Detecting OS ...', 1)
        headers = set()
        responses = self.cache.get_responses()

        # find matches in the header
        for response in responses:
            self.find_match_in_headers(response)

        # find match in current results
        self.find_match_in_results()

        # do some house keeping
        self.finalize()


class DiscoverPlatform(object):

    def __init__(self, options, data):
        self.printer = data[u'printer']
        self.requester = data[u'requester']
        self.matcher = data[u'matcher']
        self.result = data[u'results']
        self.printer = data[u'printer']
        self.threads = options[u'threads']
        self.batch_size = options[u'batch_size']
        self.queue = defaultdict(list)

        for fp_type in data[u'fingerprints'].data[u'platform']:
            for fp in data[u'fingerprints'].data[u'platform'][fp_type][u'fps']:
                self.queue[fp[u'url']].append(fp)

        # only used for pretty printing of debugging info
        self.tmp_set = set()

    def run(self):
        self.printer.print_debug_line(u'Detecting platform ...', 1)

        while len(self.queue) > 0:
            queue = []
            for i in xrange(self.batch_size):
                try:
                    url, fp_list = self.queue.popitem()
                    queue.append(fp_list)
                except KeyError:
                    break

            results = self.requester.run(u'Plaform', queue)

            # search for CMS matches
            while not results.empty():
                fingerprints, response = results.get()
                matches = self.matcher.get_result(fingerprints, response)
                for fp in matches:
                    self.result.add(u'platform', fp[u'name'], fp[u'output'], fp)

                    if (fp[u'name'], fp[u'output']) not in self.tmp_set:
                        self.printer.print_debug_line(u'- Found platform %s %s' % (fp[u'name'], fp[u'output']), 2)

                    self.tmp_set.add((fp[u'name'], fp[u'output']))


class DiscoverTitle(object):
    u"""
    Get the site title.
    """

    def __init__(self, options, data):
        self.data = data
        self.url = options[u'url']
        self.printer = data[u'printer']

    def run(self):
        self.printer.print_debug_line(u'Getting title ...', 1)
        self.data[u'requester'].run(u'Title', [[{u'url': u'/'}]])
        front_page = self.data[u'cache'][self.url]

        try:
            title = re.findall(ur'<title>\s*(.*)\s*</title>', front_page.body)[0]
            title = title.strip()
        except:
            title = u''

        try:
            self.printer.print_debug_line(u'- Found title: %s' % (title, ), 2)
        except:
            pass

        return title


class DiscoverTools(object):
    u"""
    Lists tools that can be used for further information gathering.
    """

    def __init__(self, data):
        self.translator = data[u'fingerprints'].data[u'translator'][u'dictionary']
        self.results = data[u'results']
        self.printer = data[u'printer']

    def run(self):
        self.printer.print_debug_line(u'Searching for tools ...', 1)
        cms_results = self.results.get_versions()

        # loop over the cms' in the results
        for detected_cms, _ in cms_results:
            # loop over all the translations
            for cms_name in self.translator:
                # check if the translated name is the same as the cms
                if self.translator[cms_name][u'name'] == detected_cms and u'tool' in self.translator[cms_name]:
                    for tool in self.translator[cms_name][u'tool']:
                        self.results.add_tool(detected_cms, tool[u'name'], tool[u'link'])
                        self.printer.print_debug_line(u'- Found tool: %s (%s)' % (tool[u'name'], tool[u'link']), 2)


class DiscoverUrlLess(object):
    u"""
    Test fingerprints that don't have a URL.
    """

    def __init__(self, options, data):
        self.printer = data[u'printer']
        self.cache = data[u'cache']
        self.results = data[u'results']
        self.matcher = data[u'matcher']
        self.fingerprints = data[u'fingerprints']


    def run(self):
        self.printer.print_debug_line(u'Matching urlless fingerprints...', 1)

        # only used for pretty printing of debugging info
        tmp_set = set()

        for fp_category in [u'cms', u'platform']:
            for fp_type in self.fingerprints.data[fp_category]:
                fps = self.fingerprints.data[fp_category][fp_type][u'fps']
                fps = [fp for fp in fps if fp[u'url'] == u'']

                # find matches for all the responses in the cache
                for response in self.cache.get_responses():
                    matches = self.matcher.get_result(fps, response)
                    for fp in matches:

                        url_data = urlparse(response.get_url())
                        fp[u'url'] = url_data.path

                        show_all_detections = True
                        if u'show_all_detections' in fp:
                            show_all_detections = fp[u'show_all_detections']

                        if (fp[u'name'], fp[u'output']) in tmp_set:
                            if show_all_detections:
                                self.results.add(fp_category, fp[u'name'], fp[u'output'], fingerprint=fp, weight=1)

                        else:
                            self.printer.print_debug_line(u'- Found fingerprint: %s %s' % (fp[u'name'], fp[u'output']), 2)
                            self.results.add(fp_category, fp[u'name'], fp[u'output'], fingerprint=fp, weight=1)

                        tmp_set.add((fp[u'name'], fp[u'output']))


class DiscoverVulnerabilities(object):
    u"""
    Search the database for known vulnerabilities in the
    detected CMS version
    """

    def __init__(self, data):
        self.printer = data[u'printer']
        self.results = data[u'results']
        self.fps = []

        vuln_sources = data[u'fingerprints'].data[u'vulnerabilities']

        for source in vuln_sources:
            self.fps.extend(data[u'fingerprints'].data[u'vulnerabilities'][source][u'fps'])


    def run(self):
        self.printer.print_debug_line(u'Searching for vulnerabilities ...', 1)

        cms_results = self.results.get_versions()

        vendors = Counter()
        for r in cms_results: vendors[r[0]] += 1

        # if there are more than 5 results,
        # skip displaying vuln count, as the
        # results are unreliable
        for cms, version in cms_results:
            if vendors[cms] > 5: continue

            try:
                for fp in self.fps:
                    if fp[u'name'] == cms and fp[u'version'] == version:
                        self.results.add_vulnerabilities(cms, version, fp[u'num_vulns'], fp[u'link'])
                        error = (cms, version, fp[u'num_vulns'])
                        self.printer.print_debug_line(u'- Found vulnerability: %s %s: %s' % error, 2)

            except Exception, e:
                print e
                pass
