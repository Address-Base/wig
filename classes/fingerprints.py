import json
import os
import copy


class Fingerprints(object):

    def __init__(self):
        absolute_path = os.path.dirname(os.path.realpath(__file__))
        self.data = {
            'cms': {
                'md5':          {'dir': os.path.abspath( absolute_path + '/../data/cms/md5/' ),            'fps': []},
                'reqex':        {'dir': os.path.abspath( absolute_path + '/../data/cms/regex/' ),          'fps': []},
                'string':       {'dir': os.path.abspath( absolute_path + '/../data/cms/string/' ),         'fps': []},
                'header':       {'dir': os.path.abspath( absolute_path + '/../data/cms/header/' ),         'fps': []}
            },
            'js': {
                'md5':          {'dir': os.path.abspath( absolute_path + '/../data/js/md5/' ),             'fps': []},
                'reqex':        {'dir': os.path.abspath( absolute_path + '/../data/js/regex/' ),           'fps': []},
            },
            'platform': {
                'md5':          {'dir': os.path.abspath( absolute_path + '/../data/platform/md5/' ),       'fps': []},
                'reqex':        {'dir': os.path.abspath( absolute_path + '/../data/platform/regex/' ),     'fps': []},
                'string':       {'dir': os.path.abspath( absolute_path + '/../data/platform/string/' ),    'fps': []},
                'header':       {'dir': os.path.abspath( absolute_path + '/../data/platform/header/' ),    'fps': []}
            },
            'vulnerabilities': {
                'cvedetails':   {'dir': os.path.abspath( absolute_path + '/../data/vulnerabilities/cvedetails/' ), 'fps': []},
            },
            'translator':       {'file': os.path.abspath( absolute_path + '/../data/dictionary.json' ),    'dictionary': {}},
            'error_pages':      {'file': os.path.abspath( absolute_path + '/../data/error_pages.json' ),   'fps': []},
            'interesting':      {'file': os.path.abspath( absolute_path + '/../data/interesting.json' ),   'fps': []},
            'subdomains':       {'file': os.path.abspath( absolute_path + '/../data/subdomains.json' ),    'fps': []},
            'os':               {'dir': os.path.abspath( absolute_path + '/../data/os/' ),                'fps': []}
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
        if len(filename.split('.')) == 2:
            name,ext = filename.split('.')
            is_json = ext == 'json'

        return is_json


    def _get_name(self, filename):
        name,ext = filename.split('.')
        return self.data['translator']['dictionary'][name]['name']


    def _open_file(self, filename):
        if not self._is_json(filename): return None

        try:
            with open(filename) as fh:
                fps = json.load(fh)
        except Exception as e:
            print('Error loading file: %s' % (filename))
            return None

        return fps


    def _load_subdomains(self):
        self.data['subdomains']['fps'] = self._open_file(self.data['subdomains']['file'])


    def _load_dictionary(self):
        fps = self._open_file(self.data['translator']['file'])
        if fps is not None:
            self.data['translator']['dictionary'] = fps


    def _load_error(self):
        fps = self._open_file(self.data['error_pages']['file'])
        if fps is not None:
            self.data['error_pages']['fps'] = fps


    def _load_os(self):
        for json_file in os.listdir(self.data['os']['dir']):
            fps = self._open_file(self.data['os']['dir'] + '/' + json_file)
            if fps is not None:
                self.data['os']['fps'].extend(fps)


    def _load_interesting(self):
        fps = self._open_file(self.data['interesting']['file'])

        for fp in fps:
            if 'ext' in fp:
                for ext in fp['ext']:
                    fp_copy = copy.deepcopy(fp)
                    fp_copy['url'] += '.' + ext
                    self.data['interesting']['fps'].append(fp_copy)
            else:
                self.data['interesting']['fps'].append(fp)


    def _load(self):
        categories = ['cms', 'js', 'platform', 'vulnerabilities']
        for category in categories:
            for fp_type in self.data[category]:
                for json_file in os.listdir(self.data[category][fp_type]['dir']):
                    fps = self._open_file(self.data[category][fp_type]['dir'] + '/' + json_file)
                    for fp in fps:
                        fp['name'] = self._get_name( json_file )
                        self.data[category][fp_type]['fps'].append( fp )
