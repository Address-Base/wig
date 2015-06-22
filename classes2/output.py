from __future__ import with_statement
from __future__ import absolute_import
import re, json
from io import open

class Output(object):
	def __init__(self, options, data):
		self.results = None
		self.data = data
		self.options = options

		# calc the amount of fingerprints
		fps = data[u'fingerprints'].data
		num_fps_js		= sum([len(fps[u'js'][fp_type][u'fps']) for fp_type in fps[u'js']])
		num_fps_os		= len(fps[u'os'][u'fps'])
		num_fps_cms		= sum([len(fps[u'cms'][fp_type][u'fps']) for fp_type in fps[u'cms']])
		num_fps_plat	= sum([len(fps[u'platform'][fp_type][u'fps']) for fp_type in fps[u'platform']])
		num_fps_vuln	= sum([len(fps[u'vulnerabilities'][source][u'fps']) for source in fps[u'vulnerabilities']])
		self.num_fps = num_fps_js + num_fps_os + num_fps_cms + num_fps_plat + num_fps_vuln

		self.sections = [
			{
				u'name': u'version',
				u'headers': {
					1: {u'title': u'SOFTWARE', u'color': u'blue', u'bold': True},
					2: {u'title': u'VERSION',  u'color': u'blue', u'bold': True},
					3: {u'title': u'CATEGORY',  u'color': u'blue', u'bold': True}
				},
				u'titles': [
					{u'category': u'cms',					u'title': u'CMS'},
					{u'category': u'js',					u'title': u'JavaScript'},
					{u'category': u'platform',			u'title': u'Platform'},
					{u'category': u'os',					u'title': u'Operating System'},
				]
			},
			{
				u'name': u'vulnerabilities',
				u'headers': {
					1: {u'title': u'SOFTWARE',        u'color': u'blue', u'bold': True},
					2: {u'title': u'VULNERABILITIES', u'color': u'blue', u'bold': True},
					3: {u'title': u'LINK',            u'color': u'blue', u'bold': True}
				},
				u'titles': [
					{u'category': u'vulnerability',          u'title': u'%s'},
				]
			},
			{
				u'name': u'tool',
				u'headers': {
					1: {u'title': u'TOOL',			u'color': u'blue', u'bold': True},
					2: {u'title': u'SOFTWARE',		u'color': u'blue', u'bold': True},
					3: {u'title': u'LINK',			u'color': u'blue', u'bold': True}
				},
				u'titles': [
					{u'category': u'tool',             u'title': u'%s'},
				]
			},
			{
				u'name': u'subdomains',
				u'headers': {
					1: {u'title': u'DOMAIN',			u'color': u'blue', u'bold': True},
					2: {u'title': u'TITLE',			u'color': u'blue', u'bold': True},
					3: {u'title': u'IP',				u'color': u'blue', u'bold': True}
				},
				u'titles': [
					{u'category': u'subdomains',		u'title': u'%s'},
				]
			},
			{
				u'name': u'interesting',
				u'headers':{
					1: {u'title': u'URL',				u'color': u'blue', u'bold': True},
					2: {u'title': u'NOTE',			u'color': u'blue', u'bold': True},
					3: {u'title': u'CATEGORY',		u'color': u'blue', u'bold': True}
				},
				u'titles': [
					{u'category': u'interesting',		u'title': u'Interesting URL'},
				]
			}
		]

		self.sections_names = [s[u'name'] for s in self.sections]
		self.ip = self.title = self.cookies = None

	def replace_version_text(self, text):
		# replace text in version output with something else
		# (most likely an emtpy string) to improve output
		text = re.sub(u'^wmf/', u'', text)
		text = re.sub(u'^develsnap_', u'', text)
		text = re.sub(u'^release_candidate_', u'', text)
		text = re.sub(u'^release_stable_', u'', text)
		text = re.sub(u'^release[-|_]', u'', text, flags=re.IGNORECASE)	# Umbraco, phpmyadmin
		text = re.sub(u'^[R|r][E|e][L|l]_', u'', text)				
		text = re.sub(u'^mt', u'', text)				# Movable Type
		text = re.sub(u'^mybb_', u'', text)			# myBB
		return text

	def find_section_index(self, section):
		index = 0
		for elm in self.sections:
			if elm[u'name'] == section: return index
			index += 1

		return None

	def update_stats(self):
		self.stats = {
			u'runtime':		u'Time: %.1f sec' % (self.data[u'runtime'], ),
			u'url_count':	u'Urls: %s' % (self.data[u'url_count'], ),
			u'fp_count':		u'Fingerprints: %s' % (self.num_fps, ),
		}

	def loop_results(self, section):
		versions = self.sections[self.find_section_index(section)]
		for item in versions[u'titles']:
			if item[u'category'] not in self.results: continue
			for software in sorted(self.results[item[u'category']]):
				version = self.results[item[u'category']][software]
				category = item[u'title']
				yield (category, software, version)


class OutputJSON(Output):
	def __init__(self, options, data):
		super(OutputJSON, self).__init__(options, data)
		self.json_data = []
	
	def add_results(self):
		self.results = self.data[u'results'].results
		site_info = self.data[u'results'].site_info

		site = {
			u'statistics': {
				u'start_time': self.data[u'timer'],
				u'run_time': self.data[u'runtime'],
				u'urls': self.data[u'url_count'],
				u'fingerprints': self.num_fps
			},
			u'site_info': {
				u'url': self.options[u'url'],
				u'title': site_info[u'title'],
				u'cookies': [c for c in site_info[u'cookies']],
				u'ip': site_info[u'ip']
			},
			u'data': []
		}

		# add versions
		for section in self.sections_names:
			tmp = u''
			for result in self.loop_results(section):
				category, software, version = result

				if section == u'vulnerabilities':
					site[u'data'].append({
						u'category': u'vulnerability',
						u'name': software[0],
						u'version': software[1],
						u'link': version[u'col3'],
						u'vulnerability_count': version[u'col2']
					})
				elif section == u'tool':
					site[u'data'].append({
						u'category': u'tools',
						u'name': software,
						u'version': version
					})					
				
				else:
					site[u'data'].append({
						u'category': category,
						u'name': software,
						u'version': version
					})

		self.json_data.append(site)

	def add_error(self, msg):
		self.json_data.append({
			u'site_info': {
				u'url': self.options[u'url'],
				u'error': msg
			}
		})

	def write_file(self):
		file_name = self.options[u'write_file']
		with open(file_name+ u'.json', u'w') as fh:
			fh.write(json.dumps(self.json_data, sort_keys=True, indent=4, separators=(u',', u': ')))


class OutputPrinter(Output):

	def __init__(self, options, data):
		super(OutputPrinter, self).__init__(options, data)
		self.col_widths =  {1: 0, 2: 0, 3: 0}


	def _set_col_1_width(self, results):
		self.col_widths[1] = 2 + max(
			max([len(i[u'headers'][1][u'title']) for i in self.sections]),	# length of section header titles
			max([len(p) for c in results for p in results[c]] + [0]), 			# length of software name from results
			len(self.stats[u'runtime'])										# length of status bar (time)
		)

	def _set_col_2_width(self, results):		
		self.col_widths[2] = 2 + max(
			max([ len(i[u'headers'][2][u'title']) for i in self.sections ]),							# length of section header titles
			max([ len(u' | '.join(results[c][p])) for c in results for p in results[c] ] + [0]),	# length of version details from results
			len(self.stats[u'url_count'])															# length of status bar (urls)
		)
		
	def _set_col_3_width(self, results):
		self.col_widths[3] = max(
			max([len(i[u'title']) for s in self.sections for i in s[u'titles']]),	# length of titles
			len(self.stats[u'fp_count'])												# length of status bar (fps)
		)

	def print_results(self):
		p = self.data[u'printer']

		self.results = self.data[u'results'].get_results()
		for category in self.results:
			for name in self.results[category]:
				versions = self.results[category][name]
				if len(versions) > 5:
					msg = u'... (' + unicode(len(versions)-5) + u')'
					self.results[category][name] = versions[:5] + [msg]

		self.update_stats()
		self._set_col_1_width(self.results)
		self._set_col_2_width(self.results)
		self._set_col_3_width(self.results)

		p.build_line(u'\nTITLE\n', u'blue', True)
		p.build_line(self.data[u'results'].site_info[u'title'], u'normal')
		p.print_built_line()

		if self.data[u'results'].site_info[u'cookies']:
			p.build_line(u'\nCOOKIES\n', u'blue', True)
			p.build_line(u', '.join(list(self.data[u'results'].site_info[u'cookies'])), u'normal')
			p.print_built_line()

		p.build_line(u'\nIP\n', u'blue', True)
		p.build_line(self.data[u'results'].site_info[u'ip'] + u'\n', u'normal')
		p.print_built_line()

		for section in self.sections_names:
			lines = []
			for result in self.loop_results(section):
				category, software, version = result
				
				col1 = u' '.join(list(software)) if type(software) == tuple else software
				col2 = [version[u'col2']] if u'col2' in version else version
				col3 = category % (version[u'col3'],) if u'col3' in version else category
						
				lines.append( (col1, col2, col3) )

			if lines:
				section_index = self.find_section_index(section)
				headers = self.sections[section_index][u'headers']
				col1,col2,col3 = headers[1], headers[2], headers[3]

				p.build_line(col1[u'title'], col1[u'color'], col1[u'bold'])
				p.build_line(u' ' * (self.col_widths[1] - len(col1[u'title'])), u'normal')
				p.build_line(col2[u'title'], col2[u'color'], col2[u'bold'])
				p.build_line(u' ' * (self.col_widths[2] - len(headers[2][u'title'])), u'normal')
				p.build_line(col3[u'title'], col3[u'color'], col3[u'bold'])
				p.print_built_line()

				for col1, col2, col3 in lines:
					p.build_line(col1 + u' ' * (self.col_widths[1] - len(col1)), u'normal')

					#col 2
					if len(col2) > 1:
						v = [self.replace_version_text(i) for i in col2]
						p.build_line(u' | '.join(v) + u' ' * (self.col_widths[2] - len(u' | '.join(v))), u'normal')
					else:
						v = self.replace_version_text(col2[0])
						p.build_line(v + u' ' * (self.col_widths[2] - len(v)), u'normal')

					p.build_line(col3 + u'\n', u'normal')

				p.print_built_line()

		# status bar
		time = self.stats[u'runtime']   + u' ' * (self.col_widths[1] - len(self.stats[u'runtime']))
		urls = self.stats[u'url_count'] + u' ' * (self.col_widths[2] - len(self.stats[u'url_count'])) 
		fps  = self.stats[u'fp_count']

		p.build_line(u'_'*sum(self.col_widths.values())+u'\n', u'blue', True)
		p.build_line(u''.join([ time, urls, fps ]), u'normal')
		p.print_built_line()
