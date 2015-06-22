from __future__ import absolute_import
from collections import defaultdict
from classes.color import Color

class Log(object):
	def __init__(self):
		self.logs = defaultdict(lambda: defaultdict(set))
		self.colorizer = Color()

	def __str__(self):
		out = u""

		for url in self.logs:
			out += u"Url: " + url
			for cms in self.logs[url]:
				lst = self.colorizer.format(u"[" + u", ".join(self.logs[url][cms]) + u"]", u'red', False)
				out += u"  %s: %s" % (cms, lst)
			out +=  u"\n"

		return out

	def add(self, logs):
		for url in logs:
			for cms in logs[url]:
				for version in logs[url][cms]:
					self.logs[url][cms].add(unicode(version))

