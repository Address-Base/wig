
class ExtractHeaders(object):

	def __init__(self, data, log=None):
		self.cache = data[u'cache']
		self.results = data[u'results']
		self.log = log
		self.headers = set()
		self.category = u"platform"

	def _split_server_line(self, line):
		if u"(" in line:
			os = line[line.find(u'(')+1:line.find(u')')]
			sh = line[:line.find(u'(')-1] + line[line.find(u')')+1: ]
			return os, sh
		else:
			return False, line

	def add_header(self, response):
		for header in response.headers:

			# extract the headers and values. 
			headers = [(hdr, value) for hdr, value, url in self.headers]

			# if the header and value is not in the header set, add them along with the url.
			# only the first header,value,url set should be added. 
			if not (header, response.headers[header]) in headers:
				self.headers.add((header, response.headers[header], response.url))

	def run(self):
		# get all the headers seen during the scan
		for response in self.cache.get_responses():
			self.add_header(response)

		# examine all the headers found
		for hdr,val,url in self.headers:
			
			# "server" can be used to identify the web server and operating system 
			if hdr == u'Server'.lower():

				# extract the OS if present: (Apache/2.2 (Ubuntu) PHP/5.3.1 )
				# os = Ubuntu
				# line = Apache/2.2 PHP/5.3.1
				os, line = self._split_server_line(val)
				
				out = []
				for part in line.split(u" "):
					try:
						pkg,version = part.split(u'/')
						
						# add the results to the log and the results
						#self.log.add( {url: {pkg: [version]} } )
						self.results.add(self.category, pkg, version, weight=1)
					except Exception, e:
						continue

