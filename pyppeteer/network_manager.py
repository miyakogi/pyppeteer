#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Network Manager module."""

import asyncio
import base64
from collections import OrderedDict
import copy
import json
import logging
from types import SimpleNamespace
from typing import Awaitable, Dict, List, Optional, Union, TYPE_CHECKING
from urllib.parse import unquote

from pyee import AsyncIOEventEmitter

from pyppeteer.connection import CDPSession
from pyppeteer.errors import NetworkError
from pyppeteer.helper import debugError
from pyppeteer.multimap import Multimap

EVALUATION_SCRIPT_URL = "__pyppeteer_evaluation_script__"
if TYPE_CHECKING:
    from typing import Set  # noqa: F401

logger = logging.getLogger(__name__)


class NetworkManager(AsyncIOEventEmitter):
    """NetworkManager class."""

    Events = SimpleNamespace(
        Request='request',
        Response='response',
        RequestFailed='requestfailed',
        RequestFinished='requestfinished',
    )

    def __init__(self, client: CDPSession, frameManager,
                 _ignoreHTTPSErrors) -> None:
        """Make new NetworkManager."""
        super().__init__()
        self._client = client
        self._ignoreHTTPSErrors = _ignoreHTTPSErrors
        self._frameManager = frameManager
        self._requestIdToRequest: Dict[Optional[str], Request] = dict()
        self._interceptionIdToRequest: Dict[Optional[str], Request] = dict()
        self._extraHTTPHeaders: OrderedDict[str, str] = OrderedDict()
        self._offline: bool = False
        self._credentials: Optional[Dict[str, str]] = None
        self._attemptedAuthentications: Set[str] = set()
        self._userRequestInterceptionEnabled = False
        self._protocolRequestInterceptionEnabled = False
        self._requestHashToRequestIds = Multimap()
        self._requestIdToInterceptionId = {}
        self._requestHashToInterceptionIds = Multimap()
        self._userCacheDisabled = False
        self._requestIdToRequestWillBeSentEvent = {}
        self._client.on('Fetch.requestPaused', self._onRequestPaused)
        self._client.on('Fetch.authRequired', self._onAuthRequired)

        self._client.on('Network.requestWillBeSent', self._onRequestWillBeSent)
        self._client.on('Network.requestServedFromCache',
                        self._onRequestServedFromCache)  # noqa: #501
        self._client.on('Network.responseReceived', self._onResponseReceived)
        self._client.on('Network.loadingFinished', self._onLoadingFinished)
        self._client.on('Network.loadingFailed', self._onLoadingFailed)

    async def initialize(self):
        await self._client.send('Network.enable')
        if self._ignoreHTTPSErrors:
            await self._client.send('Security.setIgnoreCertificateErrors',
                                    {"ignore": True})

    async def authenticate(self, credentials: Dict[str, str]) -> None:
        """Provide credentials for http auth."""
        self._credentials = credentials
        await self._updateProtocolRequestInterception()

    async def setExtraHTTPHeaders(self, extraHTTPHeaders: Dict[str, str]
                                  ) -> None:
        """Set extra http headers."""
        self._extraHTTPHeaders = OrderedDict()
        for k, v in extraHTTPHeaders.items():
            if not isinstance(v, str):
                raise TypeError(
                    f'Expected value of header "{k}" to be string, '
                    f'but {type(v)} is found.')
            self._extraHTTPHeaders[k.lower()] = v
        await self._client.send('Network.setExtraHTTPHeaders',
                                {'headers': self._extraHTTPHeaders})

    def extraHTTPHeaders(self) -> Dict[str, str]:
        """Get extra http headers."""
        return dict(**self._extraHTTPHeaders)

    async def setOfflineMode(self, value: bool) -> None:
        """Change offline mode enable/disable."""
        if self._offline == value:
            return
        self._offline = value
        await self._client.send('Network.emulateNetworkConditions', {
            'offline': self._offline,
            'latency': 0,
            'downloadThroughput': -1,
            'uploadThroughput': -1,
        })

    async def setUserAgent(self, userAgent: str) -> None:
        """Set user agent."""
        await self._client.send('Network.setUserAgentOverride',
                                {'userAgent': userAgent})

    async def setCacheEnabled(self, enabled):
        self._userCacheDisabled = not enabled
        await self._updateProtocolCacheDisabled()

    async def setRequestInterception(self, value: bool) -> None:
        """Enable request interception."""
        self._userRequestInterceptionEnabled = value
        await self._updateProtocolRequestInterception()

    async def _updateProtocolRequestInterception(self) -> None:
        enabled = (self._userRequestInterceptionEnabled or
                   bool(self._credentials))
        if enabled == self._protocolRequestInterceptionEnabled:
            return
        self._protocolRequestInterceptionEnabled = enabled
        if enabled:
            await asyncio.gather(
                self._updateProtocolCacheDisabled(),
                self._client.send('Fetch.enable', {
                    'handleAuthRequests': True,
                    'patterns': [{'urlPattern': '*'}]})
            )
        else:
            await asyncio.gather(
                self._updateProtocolCacheDisabled(),
                self._client.send('Fetch.disable')
            )

    async def _updateProtocolCacheDisabled(self):
        await self._client.send('Network.setCacheDisabled', {
            "cacheDisabled": self._userCacheDisabled or self._protocolRequestInterceptionEnabled
        })

    async def _send(self, method: str, msg: dict) -> None:
        try:
            await self._client.send(method, msg)
        except Exception as e:
            debugError(logger, e)

    def _onAuthRequired(self, event):
        response = 'Default'
        if event['requestId'] in self._attemptedAuthentications:
            response = 'CancelAuth'
        elif self._credentials:
            response = 'ProvideCredentials'
            self._attemptedAuthentications.add(event['requestId'])
        credentials = self._credentials or {"username": None, "password": None}
        self._client.send('Fetch.continueWithAuth', {
            "requestId": event['requestId'],
            "authChallengeResponse": {"response": response, **credentials}
        })

    def _onRequestPaused(self, event):
        if not self._userRequestInterceptionEnabled and self._protocolRequestInterceptionEnabled:
            self._client.send('Fetch.continueRequest', {
                "requestId": event['requestId']
            })
        requestId = event.get("networkId")
        interceptionId = event.get('requestId')
        requestWillBeSentEvent = self._requestIdToRequestWillBeSentEvent.pop(
            requestId, None)
        if requestId and requestWillBeSentEvent:
            self._onRequest(requestWillBeSentEvent, interceptionId)
        else:
            self._requestIdToInterceptionId[requestId] = interceptionId

    def _onRequest(self, event, interceptionId):
        redirectChain = []
        frameId = event.get("frameId")

        if event.get("redirectResponse"):
            request = self._requestIdToRequest.get(event.get("requestId"))
            if request:
                self._handleRequestRedirect(request, event['redirectResponse'])
                redirectChain = request._redirectChain
        frame = self._frameManager.frame(
            frameId) if frameId and self._frameManager else None
        request = Request(self._client, frame, interceptionId,
                          self._userRequestInterceptionEnabled, event,
                          redirectChain)
        self._requestIdToRequest[event['requestId']] = request
        self.emit(NetworkManager.Events.Request, request)

    def _onRequestServedFromCache(self, event: Dict) -> None:
        request = self._requestIdToRequest.get(event.get('requestId'))
        if request:
            request._fromMemoryCache = True

    def _handleRequestRedirect(self, request, responsePayload) -> None:
        response = Response(self._client, request, responsePayload)
        request._response = response
        request._redirectChain.append(request)
        response._bodyLoadedPromiseFulfill(
            NetworkError('Response body is unavailable for redirect response')
        )
        self._requestIdToRequest.pop(request._requestId, None)
        self._interceptionIdToRequest.pop(request._interceptionId, None)
        self._attemptedAuthentications.discard(request._interceptionId)
        self.emit(NetworkManager.Events.Response, response)
        self.emit(NetworkManager.Events.RequestFinished, request)

    def _onRequestWillBeSent(self, event: dict) -> None:
        if self._protocolRequestInterceptionEnabled and not event["request"][
            "url"].startswith("data:"):
            requestId = event['requestId']
            interceptionId = self._requestIdToInterceptionId.pop(requestId,
                                                                 None)
            if interceptionId:
                self._onRequest(event, interceptionId)
            else:
                self._requestIdToRequestWillBeSentEvent[
                    event['requestId']] = event
        else:
            self._onRequest(event, None)

    def _onResponseReceived(self, event: dict) -> None:
        request = self._requestIdToRequest.get(event['requestId'])
        # FileUpload sends a response without a matching request.
        if not request:
            return
        response = Response(self._client, request, event.get('response', {}))
        request._response = response
        self.emit(NetworkManager.Events.Response, response)

    def _onLoadingFinished(self, event: dict) -> None:
        request = self._requestIdToRequest.get(event.get('requestId', ''))
        # For certain requestIds we never receive requestWillBeSent event.
        # @see https://crbug.com/750469
        if not request:
            return
        response = request.response
        if response:
            response._bodyLoadedPromiseFulfill(None)
        self._requestIdToRequest.pop(request._requestId, None)
        self._interceptionIdToRequest.pop(request._interceptionId, None)
        self._attemptedAuthentications.discard(request._interceptionId)
        self.emit(NetworkManager.Events.RequestFinished, request)

    def _onLoadingFailed(self, event: dict) -> None:
        request = self._requestIdToRequest.get(event['requestId'])
        # For certain requestIds we never receive requestWillBeSent event.
        # @see https://crbug.com/750469
        if not request:
            return
        request._failureText = event.get('errorText')
        response = request.response
        if response:
            response._bodyLoadedPromiseFulfill(None)
        self._requestIdToRequest.pop(request._requestId, None)
        self._interceptionIdToRequest.pop(request._interceptionId, None)
        self._attemptedAuthentications.discard(request._interceptionId)
        self.emit(NetworkManager.Events.RequestFailed, request)


class Request(object):
    """Request class.

    Whenever the page sends a request, such as for a network resource, the
    following events are emitted by pyppeteer's page:

    - ``'request'``: emitted when the request is issued by the page.
    - ``'response'``: emitted when/if the response is received for the request.
    - ``'requestfinished'``: emitted when the response body is downloaded and
      the request is complete.

    If request fails at some point, then instead of ``'requestfinished'`` event
    (and possibly instead of ``'response'`` event), the ``'requestfailed'``
    event is emitted.

    If request gets a ``'redirect'`` response, the request is successfully
    finished with the ``'requestfinished'`` event, and a new request is issued
    to a redirect url.
    """

    def __init__(self, client: CDPSession, frame, interceptionId,
                 allowInterception, event, redirectChain) -> None:
        self._client = client
        self._requestId = event.get("requestId")
        self._isNavigationRequest = event.get("requestId") == event.get(
            "loaderId") and event.get("type") == 'Document'
        self._interceptionId = interceptionId
        self._allowInterception = allowInterception
        self._interceptionHandled = False
        self._response: Optional[Response] = None
        self._failureText: Optional[str] = None
        request = event['request']
        self._url = request.get("url")
        self._resourceType = event.get("type").lower()
        self._method = request.get("method")
        self._postData = request.get('postData')
        headers = request.get('headers', {})
        self._headers = {k.lower(): v for k, v in headers.items()}
        self._frame = frame
        self._redirectChain = redirectChain

        self._fromMemoryCache = False

    @property
    def url(self) -> str:
        """URL of this request."""
        return self._url

    @property
    def resourceType(self) -> str:
        """Resource type of this request perceived by the rendering engine.

        ResourceType will be one of the following: ``document``,
        ``stylesheet``, ``image``, ``media``, ``font``, ``script``,
        ``texttrack``, ``xhr``, ``fetch``, ``eventsource``, ``websocket``,
        ``manifest``, ``other``.
        """
        return self._resourceType

    @property
    def method(self) -> Optional[str]:
        """Return this request's method (GET, POST, etc.)."""
        return self._method

    @property
    def postData(self) -> Optional[str]:
        """Return post body of this request."""
        return self._postData

    @property
    def headers(self) -> Dict:
        """Return a dictionary of HTTP headers of this request.

        All header names are lower-case.
        """
        return self._headers

    @property
    def response(self) -> Optional['Response']:
        """Return matching :class:`Response` object, or ``None``.

        If the response has not been received, return ``None``.
        """
        return self._response

    @property
    def frame(self):
        """Return a matching :class:`~pyppeteer.frame_manager.frame` object.

        Return ``None`` if navigating to error page.
        """
        return self._frame

    def isNavigationRequest(self) -> bool:
        """Whether this request is driving frame's navigation."""
        return self._isNavigationRequest

    @property
    def redirectChain(self) -> List['Request']:
        """Return chain of requests initiated to fetch a resource.

        * If there are no redirects and request was successful, the chain will
          be empty.
        * If a server responds with at least a single redirect, then the chain
          will contain all the requests that were redirected.

        ``redirectChain`` is shared between all the requests of the same chain.
        """
        return copy.copy(self._redirectChain)

    def failure(self) -> Optional[Dict]:
        """Return error text.

        Return ``None`` unless this request was failed, as reported by
        ``requestfailed`` event.

        When request failed, this method return dictionary which has a
        ``errorText`` field, which contains human-readable error message, e.g.
        ``'net::ERR_RAILED'``.
        """
        if not self._failureText:
            return None
        return {'errorText': self._failureText}

    async def continue_(self, overrides: Dict = None) -> None:
        """Continue request with optional request overrides.

        To use this method, request interception should be enabled by
        :meth:`pyppeteer.page.Page.setRequestInterception`. If request
        interception is not enabled, raise ``NetworkError``.

        ``overrides`` can have the following fields:

        * ``url`` (str): If set, the request url will be changed.
        * ``method`` (str): If set, change the request method (e.g. ``GET``).
        * ``postData`` (str): If set, change the post data or request.
        * ``headers`` (dict): If set, change the request HTTP header.
        """
        if overrides is None:
            overrides = {}

        if not self._allowInterception:
            raise NetworkError('Request interception is not enabled.')
        if self._interceptionHandled:
            raise NetworkError('Request is already handled.')

        self._interceptionHandled = True
        opt = {'requestId': self._interceptionId}
        opt.update(overrides)
        try:
            await self._client.send('Fetch.continueRequest', opt)
        except Exception as e:
            debugError(logger, e)

    async def respond(self, response: Dict) -> None:  # noqa: C901
        """Fulfills request with given response.

        To use this, request interception should by enabled by
        :meth:`pyppeteer.page.Page.setRequestInterception`. Request
        interception is not enabled, raise ``NetworkError``.

        ``response`` is a dictionary which can have the following fields:

        * ``status`` (int): Response status code, defaults to 200.
        * ``headers`` (dict): Optional response headers.
        * ``contentType`` (str): If set, equals to setting ``Content-Type``
          response header.
        * ``body`` (str|bytes): Optional response body.
        """
        if self._url.startswith('data:'):
            return
        if not self._allowInterception:
            raise NetworkError('Request interception is not enabled.')
        if self._interceptionHandled:
            raise NetworkError('Request is already handled.')
        self._interceptionHandled = True

        if response.get('body') and isinstance(response['body'], str):
            responseBody: Optional[bytes] = response['body'].encode('utf-8')
        else:
            responseBody = response.get('body')

        responseHeaders = []
        if response.get('headers'):
            for key, value in response['headers'].items():
                responseHeaders.append({"name": key.lower(), "value": value})
        if response.get('contentType'):
            responseHeaders.append(
                {"name": 'content-type', "value": response['contentType']})
        if responseBody and 'content-length' not in responseHeaders:
            responseHeaders.append(
                {"name": 'content-length', "value": str(len(responseBody))})

        try:
            await self._client.send('Fetch.fulfillRequest', {
                'requestId': self._interceptionId,
                'responseCode': response.get("status", 200),
                'responseHeaders': responseHeaders,
                'body': base64.b64encode(responseBody).decode(
                    'ascii') if responseBody else None
            })

        except Exception as e:
            debugError(logger, e)

    async def abort(self, errorCode: str = 'failed') -> None:
        """Abort request.

        To use this, request interception should be enabled by
        :meth:`pyppeteer.page.Page.setRequestInterception`.
        If request interception is not enabled, raise ``NetworkError``.

        ``errorCode`` is an optional error code string. Defaults to ``failed``,
        could be one of the following:

        - ``aborted``: An operation was aborted (due to user action).
        - ``accessdenied``: Permission to access a resource, other than the
          network, was denied.
        - ``addressunreachable``: The IP address is unreachable. This usually
          means that there is no route to the specified host or network.
        - ``blockedbyclient``: The client chose to block the request.
        - ``blockedbyresponse``: The request failed because the request was
          delivered along with requirements which are not met
          ('X-Frame-Options' and 'Content-Security-Policy' ancestor check,
          for instance).
        - ``connectionaborted``: A connection timeout as a result of not
          receiving an ACK for data sent.
        - ``connectionclosed``: A connection was closed (corresponding to a TCP
          FIN).
        - ``connectionfailed``: A connection attempt failed.
        - ``connectionrefused``: A connection attempt was refused.
        - ``connectionreset``: A connection was reset (corresponding to a TCP
          RST).
        - ``internetdisconnected``: The Internet connection has been lost.
        - ``namenotresolved``: The host name could not be resolved.
        - ``timedout``: An operation timed out.
        - ``failed``: A generic failure occurred.
        """
        errorReason = errorReasons[errorCode]
        if not errorReason:
            raise NetworkError('Unknown error code: {}'.format(errorCode))
        if not self._allowInterception:
            raise NetworkError('Request interception is not enabled.')
        if self._interceptionHandled:
            raise NetworkError('Request is already handled.')
        self._interceptionHandled = True
        try:
            await self._client.send('Fetch.failRequest', {
                "requestId": self._interceptionId,
                "errorReason": errorReason
            })
        except Exception as e:
            debugError(logger, e)


errorReasons = {
    'aborted': 'Aborted',
    'accessdenied': 'AccessDenied',
    'addressunreachable': 'AddressUnreachable',
    'blockedbyclient': 'BlockedByClient',
    'blockedbyresponse': 'BlockedByResponse',
    'connectionaborted': 'ConnectionAborted',
    'connectionclosed': 'ConnectionClosed',
    'connectionfailed': 'ConnectionFailed',
    'connectionrefused': 'ConnectionRefused',
    'connectionreset': 'ConnectionReset',
    'internetdisconnected': 'InternetDisconnected',
    'namenotresolved': 'NameNotResolved',
    'timedout': 'TimedOut',
    'failed': 'Failed',
}


class Response(object):
    """Response class represents responses which are received by ``Page``."""

    def __init__(self, client: CDPSession, request, responsePayload) -> None:
        self._client = client
        self._request = request
        self._status = responsePayload.get('status')
        self._contentPromise = self._client._loop.create_future()
        self._bodyLoadedPromise = self._client._loop.create_future()

        self._url = request.url
        self._fromDiskCache = bool(responsePayload.get('fromDiskCache', False))
        self._fromServiceWorker = bool(
            responsePayload.get('fromServiceWorker', False))
        self._headers = {k.lower(): v for k, v in
                         responsePayload.get("headers", {}).items()}
        self._securityDetails: Union[Dict, SecurityDetails] = {}
        securityDetails = responsePayload.get("securityDetails")
        if securityDetails:
            self._securityDetails = SecurityDetails(
                securityDetails['subjectName'],
                securityDetails['issuer'],
                securityDetails['validFrom'],
                securityDetails['validTo'],
                securityDetails['protocol'],
            )

    def _bodyLoadedPromiseFulfill(self, value: Optional[Exception]) -> None:
        self._bodyLoadedPromise.set_result(value)

    @property
    def url(self) -> str:
        """URL of the response."""
        return self._url

    @property
    def ok(self) -> bool:
        """Return bool whether this request is successful (200-299) or not."""
        return self._status == 0 or 200 <= self._status <= 299

    @property
    def status(self) -> int:
        """Status code of the response."""
        return self._status

    @property
    def headers(self) -> Dict:
        """Return dictionary of HTTP headers of this response.

        All header names are lower-case.
        """
        return self._headers

    @property
    def securityDetails(self) -> Union[Dict, 'SecurityDetails']:
        """Return security details associated with this response.

        Security details if the response was received over the secure
        connection, or `None` otherwise.
        """
        return self._securityDetails

    async def _bufread(self) -> bytes:
        result = await self._bodyLoadedPromise
        if isinstance(result, Exception):
            raise result
        response = await self._client.send('Network.getResponseBody', {
            'requestId': self._request._requestId
        })
        body = response.get('body', b'')
        if response.get('base64Encoded'):
            return base64.b64decode(body)
        return body

    def buffer(self) -> Awaitable[bytes]:
        """Return awaitable which resolves to bytes with response body."""
        if not self._contentPromise.done():
            return self._client._loop.create_task(self._bufread())
        return self._contentPromise

    async def text(self) -> str:
        """Get text representation of response body."""
        content = await self.buffer()
        if isinstance(content, str):
            return content
        else:
            return content.decode('utf-8')

    async def json(self) -> dict:
        """Get JSON representation of response body."""
        content = await self.text()
        return json.loads(content)

    @property
    def request(self) -> Request:
        """Get matching :class:`Request` object."""
        return self._request

    @property
    def fromCache(self) -> bool:
        """Return ``True`` if the response was served from cache.

        Here `cache` is either the browser's disk cache or memory cache.
        """
        return self._fromDiskCache or self._request._fromMemoryCache

    @property
    def fromServiceWorker(self) -> bool:
        """Return ``True`` if the response was served by a service worker."""
        return self._fromServiceWorker


def generateRequestHash(request: dict) -> str:
    """Generate request hash."""
    normalizedURL = request.get('url', '')
    try:
        normalizedURL = unquote(normalizedURL)
    except Exception:
        pass

    _hash = {
        'url': normalizedURL,
        'method': request.get('method'),
        'postData': request.get('postData'),
        'headers': {},
    }

    if not normalizedURL.startswith('data:'):
        headers = list(request['headers'].keys())
        headers.sort()
        for header in headers:
            headerValue = request['headers'][header]
            header = header.lower()
            if header in [
                'accept',
                'referer',
                'x-devtools-emulate-network-conditions-client-id',
                'cookie',
            ]:
                continue
            _hash['headers'][header] = headerValue
    return json.dumps(_hash)


class SecurityDetails(object):
    """Class represents responses which are received by page."""

    def __init__(self, subjectName: str, issuer: str, validFrom: int,
                 validTo: int, protocol: str) -> None:
        self._subjectName = subjectName
        self._issuer = issuer
        self._validFrom = validFrom
        self._validTo = validTo
        self._protocol = protocol

    @property
    def subjectName(self) -> str:
        """Return the subject to which the certificate was issued to."""
        return self._subjectName

    @property
    def issuer(self) -> str:
        """Return a string with the name of issuer of the certificate."""
        return self._issuer

    @property
    def validFrom(self) -> int:
        """Return UnixTime of the start of validity of the certificate."""
        return self._validFrom

    @property
    def validTo(self) -> int:
        """Return UnixTime of the end of validity of the certificate."""
        return self._validTo

    @property
    def protocol(self) -> str:
        """Return string of with the security protocol, e.g. "TLS1.2"."""
        return self._protocol


statusTexts = {
    '100': 'Continue',
    '101': 'Switching Protocols',
    '102': 'Processing',
    '200': 'OK',
    '201': 'Created',
    '202': 'Accepted',
    '203': 'Non-Authoritative Information',
    '204': 'No Content',
    '206': 'Partial Content',
    '207': 'Multi-Status',
    '208': 'Already Reported',
    '209': 'IM Used',
    '300': 'Multiple Choices',
    '301': 'Moved Permanently',
    '302': 'Found',
    '303': 'See Other',
    '304': 'Not Modified',
    '305': 'Use Proxy',
    '306': 'Switch Proxy',
    '307': 'Temporary Redirect',
    '308': 'Permanent Redirect',
    '400': 'Bad Request',
    '401': 'Unauthorized',
    '402': 'Payment Required',
    '403': 'Forbidden',
    '404': 'Not Found',
    '405': 'Method Not Allowed',
    '406': 'Not Acceptable',
    '407': 'Proxy Authentication Required',
    '408': 'Request Timeout',
    '409': 'Conflict',
    '410': 'Gone',
    '411': 'Length Required',
    '412': 'Precondition Failed',
    '413': 'Payload Too Large',
    '414': 'URI Too Long',
    '415': 'Unsupported Media Type',
    '416': 'Range Not Satisfiable',
    '417': 'Expectation Failed',
    '418': 'I\'m a teapot',
    '421': 'Misdirected Request',
    '422': 'Unprocessable Entity',
    '423': 'Locked',
    '424': 'Failed Dependency',
    '426': 'Upgrade Required',
    '428': 'Precondition Required',
    '429': 'Too Many Requests',
    '431': 'Request Header Fields Too Large',
    '451': 'Unavailable For Legal Reasons',
    '500': 'Internal Server Error',
    '501': 'Not Implemented',
    '502': 'Bad Gateway',
    '503': 'Service Unavailable',
    '504': 'Gateway Timeout',
    '505': 'HTTP Version Not Supported',
    '506': 'Variant Also Negotiates',
    '507': 'Insufficient Storage',
    '508': 'Loop Detected',
    '510': 'Not Extended',
    '511': 'Network Authentication Required',
}
