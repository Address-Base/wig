from __future__ import absolute_import
import os


class Printer(object):
	def __init__(self, global_verbosity):
		self.verbosity = global_verbosity

		self.verbosity_colors = [
			{u'verbosity_level': 0, u'name': u'red', u'code': u'31'},
			{u'verbosity_level': 1, u'name': u'yellow', u'code': u'33'},
			{u'verbosity_level': 2, u'name': u'cyan', u'code': u'36'},
			{u'verbosity_level': 3, u'name': u'blue', u'code': u'34'},
			{u'verbosity_level': 4, u'name': u'green', u'code': u'32'},
			{u'verbosity_level': 5, u'name': u'magenta', u'code': u'35'},
			{u'verbosity_level': 6, u'name': u'normal', u'code': None},
		]

		self.current_line = u''

	def _find_color_by_name(self, name):
		for color in self.verbosity_colors:
			if color[u'name'] == name: return color[u'code']
		else:
			return None

	def _find_color_by_verbosity(self, verbosity):
		for color in self.verbosity_colors:
			if color[u'verbosity_level'] == verbosity: return color[u'code']
		else:
			return None

	def _format(self, string, color_code=None, bold=False):
		attr = []

		# bail if OS is windows
		# note: cygwin show be detected as 'posix'
		if os.name == u'nt': return string

		attr = [color_code] if color_code is not None else []

		if bold: attr.append(u'1')
		
		return u'\x1b[%sm%s\x1b[0m' % (u';'.join(attr), string)		

	def build_line(self, text, color=u'normal', bold=False):
		color_code = self._find_color_by_name(color)
		self.current_line += self._format(text, color_code, bold)
	
	def print_built_line(self):
		try:
			if self.verbosity >= 0:
				if not self.current_line == u'':
					print self.current_line
				self.current_line = u''
		except Exception, e:
			self.current_line = u''
			pass

	def print_debug_line(self, text, verbosity, bold=False):
		if self.verbosity >= verbosity:
			color = self._find_color_by_verbosity(verbosity)
			print self._format(text, color, bold)

	def print_logo(self):
		logo = u"""\nwig - WebApp Information Gatherer\n\n"""
		if self.verbosity >= 0:
			print logo
