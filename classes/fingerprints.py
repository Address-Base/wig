from __future__ import with_statement
from __future__ import absolute_import
import json
import os
import copy
from io import open


class Fingerprints(object):

	def __init__(self):
		
		self.data = {
			u'cms': {
				u'md5':			{u'dir': u'data/cms/md5/',			u'fps': []},
				u'reqex':		{u'dir': u'data/cms/regex/',			u'fps': []},
				u'string':		{u'dir': u'data/cms/string/',			u'fps': []},
				u'header':		{u'dir': u'data/cms/header/',			u'fps': []}
			},
			u'js': {
				u'md5':			{u'dir': u'data/js/md5/',				u'fps': []},
				u'reqex':		{u'dir': u'data/js/regex/',			u'fps': []},
			},
			u'platform': {
				u'md5':			{u'dir': u'data/platform/md5/',		u'fps': []},
				u'reqex':		{u'dir': u'data/platform/regex/',		u'fps': []},
				u'string':		{u'dir': u'data/platform/string/',	u'fps': []},
				u'header':		{u'dir': u'data/platform/header/',	u'fps': []}
			},
			u'vulnerabilities': {
				u'cvedetails':	{u'dir':  u'data/vulnerabilities/cvedetails/', u'fps': []},
			},
			u'translator':		{u'file': u'data/dictionary.json',	u'dictionary': {}},
			u'error_pages':		{u'file': u'data/error_pages.json',	u'fps': []},
			u'interesting':		{u'file': u'data/interesting.json',	u'fps': []},
			u'subdomains':		{u'file': u'data/subdomains.json',	u'fps': []},
			u'os':				{u'dir':  u'data/os/',				u'fps': []}
		}

		# load fingerprints
		self._load_subdomains()
		self._load_dictionary()
		self._load_interesting()
		self._load_error()
		self._load_os()
		self._load()


	def _is_json(self, filename):
		is_json = False
		if len(filename.split(u'.')) == 2:
			name,ext = filename.split(u'.')		
			is_json = ext == u'json'

		return is_json


	def _get_name(self, filename):
		name,ext = filename.split(u'.')
		return self.data[u'translator'][u'dictionary'][name][u'name']


	def _open_file(self, filename):
		if not self._is_json(filename): return None
		
		try:
			with open(filename) as fh:
				fps = json.load(fh)
		except Exception, e:
			print u'Error loading file: %s' % (filename)
			return None

		return fps
			

	def _load_subdomains(self):
		self.data[u'subdomains'][u'fps'] = self._open_file(self.data[u'subdomains'][u'file'])


	def _load_dictionary(self):
		fps = self._open_file(self.data[u'translator'][u'file'])
		if fps is not None: 
			self.data[u'translator'][u'dictionary'] = fps


	def _load_error(self):
		fps = self._open_file(self.data[u'error_pages'][u'file'])
		if fps is not None: 
			self.data[u'error_pages'][u'fps'] = fps


	def _load_os(self):
		for json_file in os.listdir(self.data[u'os'][u'dir']): 
			fps = self._open_file(self.data[u'os'][u'dir'] + u'/' + json_file)
			if fps is not None: 
				self.data[u'os'][u'fps'].extend(fps)


	def _load_interesting(self):
		fps = self._open_file(self.data[u'interesting'][u'file'])

		for fp in fps:
			if u'ext' in fp:
				for ext in fp[u'ext']:
					fp_copy = copy.deepcopy(fp)
					fp_copy[u'url'] += u'.' + ext
					self.data[u'interesting'][u'fps'].append(fp_copy)
			else:
				self.data[u'interesting'][u'fps'].append(fp)


	def _load(self):
		categories = [u'cms', u'js', u'platform', u'vulnerabilities']
		for category in categories:
			for fp_type in self.data[category]:
				for json_file in os.listdir(self.data[category][fp_type][u'dir']): 
					fps = self._open_file(self.data[category][fp_type][u'dir'] + u'/' + json_file)
					for fp in fps:
						fp[u'name'] = self._get_name( json_file )
						self.data[category][fp_type][u'fps'].append( fp )
