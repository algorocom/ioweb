import pycurl

"""
m['effective-url'] = self.handle.getinfo(pycurl.EFFECTIVE_URL)
m['http-code'] = self.handle.getinfo(pycurl.HTTP_CODE)
m['total-time'] = self.handle.getinfo(pycurl.TOTAL_TIME)
m['namelookup-time'] = self.handle.getinfo(pycurl.NAMELOOKUP_TIME)
m['connect-time'] = self.handle.getinfo(pycurl.CONNECT_TIME)
m['pretransfer-time'] = self.handle.getinfo(pycurl.PRETRANSFER_TIME)
m['redirect-time'] = self.handle.getinfo(pycurl.REDIRECT_TIME)
m['redirect-count'] = self.handle.getinfo(pycurl.REDIRECT_COUNT)
m['size-upload'] = self.handle.getinfo(pycurl.SIZE_UPLOAD)
m['size-download'] = self.handle.getinfo(pycurl.SIZE_DOWNLOAD)
m['speed-upload'] = self.handle.getinfo(pycurl.SPEED_UPLOAD)
m['header-size'] = self.handle.getinfo(pycurl.HEADER_SIZE)
m['request-size'] = self.handle.getinfo(pycurl.REQUEST_SIZE)
m['content-length-download'] = self.handle.getinfo(pycurl.CONTENT_LENGTH_DOWNLOAD)
m['content-length-upload'] = self.handle.getinfo(pycurl.CONTENT_LENGTH_UPLOAD)
m['content-type'] = self.handle.getinfo(pycurl.CONTENT_TYPE)
m['response-code'] = self.handle.getinfo(pycurl.RESPONSE_CODE)
m['speed-download'] = self.handle.getinfo(pycurl.SPEED_DOWNLOAD)
m['ssl-verifyresult'] = self.handle.getinfo(pycurl.SSL_VERIFYRESULT)
m['filetime'] = self.handle.getinfo(pycurl.INFO_FILETIME)
m['starttransfer-time'] = self.handle.getinfo(pycurl.STARTTRANSFER_TIME)
m['redirect-time'] = self.handle.getinfo(pycurl.REDIRECT_TIME)
m['redirect-count'] = self.handle.getinfo(pycurl.REDIRECT_COUNT)
m['http-connectcode'] = self.handle.getinfo(pycurl.HTTP_CONNECTCODE)
m['httpauth-avail'] = self.handle.getinfo(pycurl.HTTPAUTH_AVAIL)
m['proxyauth-avail'] = self.handle.getinfo(pycurl.PROXYAUTH_AVAIL)
m['os-errno'] = self.handle.getinfo(pycurl.OS_ERRNO)
m['num-connects'] = self.handle.getinfo(pycurl.NUM_CONNECTS)
m['ssl-engines'] = self.handle.getinfo(pycurl.SSL_ENGINES)
m['cookielist'] = self.handle.getinfo(pycurl.INFO_COOKIELIST)
m['lastsocket'] = self.handle.getinfo(pycurl.LASTSOCKET)
m['ftp-entry-path'] = self.handle.getinfo(pycurl.FTP_ENTRY_PATH)
"""

class CurlTransport(object):
    __slots__ = (
        '_handler',
    )

    def __init__(self):
        self._handler = None

    def prepare_request(self, req, res):
        self.handler # ensure pycurl object is created
        self._handler.setopt(pycurl.URL, req.config['url'])
        self._handler.setopt(
            pycurl.WRITEFUNCTION, res.write_bytes_body,
        )
        self._handler.setopt(
            pycurl.HEADERFUNCTION, res.write_bytes_headers,
        )
        self._handler.setopt(pycurl.FOLLOWLOCATION, 0)
        self._handler.setopt(
            pycurl.OPT_CERTINFO,
            1 if req.config['certinfo'] else 0
        )
        self._handler.setopt(pycurl.SSL_VERIFYPEER, 0)
        self._handler.setopt(pycurl.SSL_VERIFYHOST, 0)
        self._handler.setopt(pycurl.TIMEOUT, req['timeout'])
        self._handler.setopt(pycurl.CONNECTTIMEOUT, req['connect_timeout'])
        if req['resolve']:
            self._handler.setopt(pycurl.RESOLVE, req['resolve'])
        if req['headers']:
            self._handler.setopt(
                pycurl.HTTPHEADER,
                ['%s: %s' %x for x in req['headers'].items()]
            )

    @property
    def handler(self):
        if not self._handler:
            self._handler = pycurl.Curl()
        return self._handler

    def set_handler(self, hdl):
        self._handler = hdl

    def close_handler(self):
        self.handler.close()

    def prepare_response(self, req, res, err):
        if err:
            res.error = err
        else:
            if req.config['certinfo']:
                res.certinfo = (
                    self._handler.getinfo(pycurl.INFO_CERTINFO)
                )
            res.status = self._handler.getinfo(pycurl.HTTP_CODE)

    def request(self):
        try:
            self.handler.perform()
        except pycurl.error as ex:
            raise build_network_error(ex.args[0], ex.args[1])
