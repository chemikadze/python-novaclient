# Copyright 2010 Jacob Kaplan-Moss
# Copyright 2011 Piston Cloud Computing

"""
OpenStack Client interface. Handles the REST calls and responses.
"""

import time
import urlparse
import urllib
import httplib2
import logging

try:
    import json
except ImportError:
    import simplejson as json

# Python 2.5 compat fix
if not hasattr(urlparse, 'parse_qsl'):
    import cgi
    urlparse.parse_qsl = cgi.parse_qsl


from novaclient import exceptions


_logger = logging.getLogger(__name__)


class HTTPClient(httplib2.Http):

    USER_AGENT = 'python-novaclient'

    def __init__(self, user, apikey, projectid, auth_url, timeout=None):
        super(HTTPClient, self).__init__(timeout=timeout)
        self.user = user
        self.apikey = apikey
        self.projectid = projectid
        self.auth_url = auth_url
        self.version = 'v1.0'

        self.management_url = None
        self.auth_token = None

        # httplib2 overrides
        self.force_exception_to_status_code = True

    def http_log(self, args, kwargs, resp, body):
        if not _logger.isEnabledFor(logging.DEBUG):
            return

        string_parts = ['curl -i']
        for element in args:
            if element in ('GET', 'POST'):
                string_parts.append(' -X %s' % element)
            else:
                string_parts.append(' %s' % element)

        for element in kwargs['headers']:
            header = ' -H "%s: %s"' % (element, kwargs['headers'][element])
            string_parts.append(header)

        _logger.debug("REQ: %s\n" % "".join(string_parts))
        _logger.debug("RESP:%s %s\n", resp, body)

    def request(self,  *args, **kwargs):
        kwargs.setdefault('headers', {})
        kwargs['headers']['User-Agent'] = self.USER_AGENT
        if 'body' in kwargs:
            kwargs['headers']['Content-Type'] = 'application/json'
            kwargs['body'] = json.dumps(kwargs['body'])
        if 'nothrow' in kwargs:
            nothrow = kwargs['nothrow']
            kwargs.pop('nothrow')
        else:
            nothrow = False

        resp, body = super(HTTPClient, self).request(*args, **kwargs)

        self.http_log(args, kwargs, resp, body)

        if body:
            try:
                body = json.loads(body)
            except ValueError, e:
                pass
        else:
            body = None

        if not nothrow and resp.status in (400, 401, 403, 404, 408, 413, 500, 501):
            raise exceptions.from_response(resp, body)

        return resp, body

    def _cs_request(self, url, method, **kwargs):
        if not self.management_url:
            self.authenticate()

        # Perform the request once. If we get a 401 back then it
        # might be because the auth token expired, so try to
        # re-authenticate and try again. If it still fails, bail.
        try:
            kwargs.setdefault('headers', {})['X-Auth-Token'] = self.auth_token
            if self.projectid:
                kwargs['headers']['X-Auth-Project-Id'] = self.projectid

            resp, body = self.request(self.management_url + url, method,
                                      **kwargs)
            return resp, body
        except exceptions.Unauthorized, ex:
            try:
                self.authenticate()
                resp, body = self.request(self.management_url + url, method,
                                          **kwargs)
                return resp, body
            except exceptions.Unauthorized:
                raise ex

    def get(self, url, **kwargs):
        url = self._munge_get_url(url)
        return self._cs_request(url, 'GET', **kwargs)

    def post(self, url, **kwargs):
        return self._cs_request(url, 'POST', **kwargs)

    def put(self, url, **kwargs):
        return self._cs_request(url, 'PUT', **kwargs)

    def delete(self, url, **kwargs):
        return self._cs_request(url, 'DELETE', **kwargs)

    def authenticate(self):
        scheme, netloc, path, query, frag = urlparse.urlsplit(
                                                    self.auth_url)

        auth_url = self.auth_url
        version = self._get_version_from_url(auth_url)
        fallbacks = self._auth_versions()
        base_url = ''
        while auth_url:
            if not version:  # in case of redirects we try fallback versions
                version = fallbacks.next()
                base_url = auth_url
                auth_url = urlparse.urljoin(base_url, version+'/')
            maj_version = version[:2]
            try:  # get auth functions by version string
                req_f = getattr(self, '_%s_auth_request' % maj_version)
                resp_f = getattr(self, '_token_from_%s_response' % maj_version)
            except AttributeError:
                raise exceptions.ClientException(501,
                                     'This protocol version is not supported')
            resp, body = req_f(auth_url)
            if resp.status in (200, 204):
                try:
                    return resp_f(resp, body)
                except KeyError:
                    pass
            elif resp.status == 305:
                auth_url = resp['location']
                version = self._get_version_from_url(auth_url)
                continue
            if not base_url:  # in normal cases we fail
                raise exceptions.Unauthorized(resp.status, message=body)
            else:  # try another fallback
                auth_url = base_url
                version = ''

    def _auth_versions(self):
        for v in ('v1.0', 'v2.0'):
            yield v

    def _get_version_from_url(self, url):
        path = urlparse.urlsplit(url)[2]
        path_parts = path.split('/')
        for part in path_parts:
            if len(part) > 0 and part[0] == 'v':
                return part
        return ''

    def _v1_auth_request(self, url):
        headers = {'X-Auth-User': self.user,
                   'X-Auth-Key': self.apikey}
        if self.projectid:
            headers['X-Auth-Project-Id'] = self.projectid

        return self.request(url, 'GET', headers=headers, nothrow=True)

    def _v2_auth_request(self, url):
        body = {"passwordCredentials": {"username": self.user,
                                        "password": self.apikey}}

        if self.projectid:
            body['passwordCredentials']['tenantId'] = self.projectid

        token_url = urlparse.urljoin(url, "tokens")
        return self.request(token_url, "POST", body=body, nothrow=True)

    def _token_from_v1_response(self, resp, body):
        self.management_url = resp['x-server-management-url']
        self.auth_token = resp['x-auth-token']

    def _token_from_v2_response(self, resp, body):
        self.management_url = body["auth"]["serviceCatalog"] \
                                  ["nova"][0]["publicURL"]
        self.auth_token = body["auth"]["token"]["id"]

        #TODO(chris): Implement service_catalog
        self.service_catalog = None


    def _munge_get_url(self, url):
        """
        Munge GET URLs to always return uncached content.

        The OpenStack Compute API caches data *very* agressively and doesn't
        respect cache headers. To avoid stale data, then, we append a little
        bit of nonsense onto GET parameters; this appears to force the data not
        to be cached.
        """
        scheme, netloc, path, query, frag = urlparse.urlsplit(url)
        query = urlparse.parse_qsl(query)
        query.append(('fresh', str(time.time())))
        query = urllib.urlencode(query)
        return urlparse.urlunsplit((scheme, netloc, path, query, frag))
