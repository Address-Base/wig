from __future__ import division
from __future__ import absolute_import
from collections import defaultdict, Counter

from .sitemap import Sitemap


class Results(object):

	def __init__(self, options):
		self.width = None
		self.printer = None
		self.results = {}

		# the storage for 'string' and 'regex' matched fingerprints
		# since these don't need extra processing they are added directly
		# to the final scores
		self.scores = defaultdict(lambda: defaultdict(lambda: Counter()))
		#		      ^ Category          ^ Name              ^ Version

		# md5 fingerprints are based on content that might not hav been changed
		# across different versions of the cms. The score of a match is based on
		# the number of 'hits' for that URL. The finale score for a cms version will be:
		#  1 / number_of_hits
		#
		self.md5_matches = defaultdict(lambda: defaultdict(lambda: Counter()))
		#		           ^ Url               ^ cms               ^ versions

		self.sitemap = Sitemap()

		self.site_info = {
			u'ip': u'',
			u'title': u'',
			u'cookies': set(),
			u'subdomains': set(),
		}

	def _calc_md5_score(self):
		# calculate the final scores for md5 fingerprints, and add
		# them to the final scores
		for url in self.md5_matches:
			for cat_name in self.md5_matches[url]:
				category, name = cat_name

				# get the number of 'hits' for a specific CMS and URL
				number_of_hits = sum([self.md5_matches[url][cat_name][version] for version in self.md5_matches[url][cat_name]])

				# update the score for the cms version
				for version in self.md5_matches[url][cat_name]:
					self.scores[category][name][version] += (1 / number_of_hits)


	def add(self, category, name, version=None, fingerprint=None, weight=1):
		url = u''
		match_type = u''

		if fingerprint is not None:
			match_type = fingerprint[u'type']

			# overwrite weight if defined in fingerprint
			if u'weight' in fingerprint:
				weight = fingerprint[u'weight']

			# add to the sitemap
			if u'url' in fingerprint:
				self.sitemap.add(fingerprint[u'url'])
				url = fingerprint[u'url']
			else:
				url = u''

			# add note if present
			if u'note' in fingerprint:
				note = fingerprint[u'note']
				self.printer.print_debug_line(u'- %s: %s' % (note, url), 5)
				self.scores[u"interesting"][url][note] += weight

		self.printer.print_debug_line(u'- Found match: %s - %s %s - %s' % (url, name, version, match_type), 5)

		#print(category, name, version, weight)
		# if the type of the fingerprint is md5, then the we need
		# to keep track of how many cms versions have been detected
		# the a given URL, as this determines the weight score of
		# fingerprint match
		if match_type == u'md5':
			self.md5_matches[url][(category, name)][version] += 1

		# if there has been no version detection (interesting file discovery)
		# skip adding the versions to the scores
		elif version == None:
			pass

		# if the version is blank or true, add '0' to
		# set it to the worst match
		elif version == u'' or version == True:
			self.scores[category][name][version] += 0

		# else add the weight
		else:
			self.scores[category][name][version] += weight


	def update(self):
		self._calc_md5_score()
		for category in self.scores:

			# initiate the entry for the category
			if category not in self.results: self.results[category] = {}

			# loop over the entries for the category
			for name in sorted(self.scores[category]):

				# get the versions and remove the ones that are most unlikely
				v = self.scores[category][name]
				versions = sorted(v.items(), key=lambda x:x[1], reverse=True)

				# if the highest rated version is blank, move it to the end of the list
				if versions[0][0] == u'':
					versions = versions[1:] + [versions[0]]

				relevant = sorted(i[0] for i in versions if i[1] == versions[0][1])
				self.results[category][name] = relevant

		self.is_updated = True


	def add_vulnerabilities(self, cms, version, num_vuln, link):
		if u'vulnerability' not in self.results: self.results[u'vulnerability'] = {}
		self.results[u'vulnerability'][(cms,version)] = {u'col2': num_vuln, u'col3': link}


	def add_tool(self, cms, tool_name, tool_link):
		if u'tool' not in self.results:
			self.results[u'tool'] = {}

		self.results[u'tool'][tool_name] = {u'col2': cms, u'col3': tool_link}


	def add_subdomain(self, subdomain, title, ip):
		if u'subdomains' not in self.results:
			self.results[u'subdomains'] = {}

		self.results[u'subdomains'][subdomain] = {u'col2': title, u'col3': ip}


	def get_versions(self):
		versions = []
		for cat in [u'cms', u'javascript', u'os', u'platform']:
			if cat not in self.results: continue
			for cms in self.results[cat]:
				for version in self.results[cat][cms]:
					versions.append( (cms, version) )

		return versions


	def get_sitemap(self):
		return unicode(self.sitemap)


	def get_platform_results(self):
		return self.scores[u'platform']


	def get_results(self):
		return self.results
