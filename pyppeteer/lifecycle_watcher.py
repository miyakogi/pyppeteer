#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Lifecycle Watcher module."""

import asyncio
import logging
import concurrent.futures
from typing import Awaitable, List

from pyppeteer import helper
from pyppeteer.frame_manager import FrameManager, Frame
from pyppeteer.network_manager import NetworkManager
from pyppeteer.connection import CDPSession
from pyppeteer.errors import TimeoutError, NetworkError


class LifecycleWatcher:
    """LifecycleWatcher class"""

    def __init__(self, frameManager: FrameManager, frame: Frame,
                 waitUntil: str, timeout: int) -> None:
        if isinstance(waitUntil, list):
            waitUntil = waitUntil[::]
        elif isinstance(waitUntil, str):
            waitUntil = [waitUntil]
        if "documentloaded" in waitUntil:
            logging.getLogger(__name__).warning(
                '`documentloaded` option is no longer supported. '
                'Use `domcontentloaded` instead.')
        self._hasSameDocumentNavigation = False
        self._expectedLifecycle: List[str] = []
        for value in waitUntil:
            protocolEvent = pyppeteerToProtocolLifecycle.get(value)
            if protocolEvent is None:
                raise ValueError(
                    f'Unknown value for options.waitUntil: {value}')
            self._expectedLifecycle.append(protocolEvent)

        self._maximumTimer = None
        self._timeoutOrTermination = None
        self._frameManager = frameManager
        self._loop = self._frameManager._client._loop
        self._frame = frame
        self._initialLoaderId = frame._loaderId
        self._timeout = timeout
        self._navigationRequest = None
        self._eventListeners = [
            helper.addEventListener(frameManager._client,
                                    CDPSession.Events.Disconnected,
                                    lambda: self._terminate(NetworkError(
                                        'Navigation failed because browser has disconnected!'))
                                    ),
            helper.addEventListener(self._frameManager,
                                    FrameManager.Events.LifecycleEvent,
                                    self._checkLifecycleComplete),
            helper.addEventListener(self._frameManager,
                                    FrameManager.Events.FrameNavigatedWithinDocument,
                                    self._navigatedWithinDocument),
            helper.addEventListener(self._frameManager,
                                    FrameManager.Events.FrameDetached,
                                    self._onFrameDetached),
            helper.addEventListener(self._frameManager.NetworkManager,
                                    NetworkManager.Events.Request,
                                    self._onRequest),

        ]
        self._timeoutPromise = self._createTimeoutPromise()
        self._sameDocumentNavigationPromise = self._loop.create_future()
        self._lifecyclePromise = self._loop.create_future()
        self._newDocumentNavigationPromise = self._loop.create_future()
        self._terminationPromise = self._loop.create_future()
        self._checkLifecycleComplete()

    def _checkLifecycle(self, frame, expectedLifecycle):
        for event in expectedLifecycle:
            if event not in frame._lifecycleEvents:
                return False
        for child in frame.childFrames:
            if not self._checkLifecycle(child, expectedLifecycle):
                return False
        return True

    def _terminate(self, error):
        self._terminationPromise.set_exception(error)

    def _onRequest(self, request):
        if request.frame != self._frame or not request.isNavigationRequest():
            return
        self._navigationRequest = request

    def _onFrameDetached(self, frame: Frame = None):
        if self._frame == frame:
            self._terminationPromise.set_exception(
                NetworkError("Navigating frame was detached"))
        else:
            self._checkLifecycleComplete()

    def navigationResponse(self):
        if self._navigationRequest:
            return self._navigationRequest.response

    @property
    def timeoutOrTerminationPromise(self):
        if asyncio.iscoroutine(self._timeoutOrTermination):
            self._timeoutOrTermination.cancel()
        self._timeoutOrTermination = self._loop.create_future()

        async def _timeoutOrTermination():
            done, pending = await asyncio.wait([
                self._timeoutPromise,
                self._terminationPromise,
            ], return_when=concurrent.futures.FIRST_COMPLETED)
            error = done.pop()
            if error.exception():
                self._timeoutOrTermination.set_exception(
                    error.exception())

        task = self._loop.create_task(_timeoutOrTermination())
        self._timeoutOrTermination.add_done_callback(
            lambda x: task.cancel())
        return self._timeoutOrTermination

    def _createTimeoutPromise(self) -> Awaitable[None]:
        self._maximumTimer = self._loop.create_future()
        if self._timeout:
            errorMessage = f'Navigation Timeout Exceeded: {self._timeout} ms exceeded.'  # noqa: E501

            async def _timeout_func() -> None:
                await asyncio.sleep(self._timeout / 1000)
                self._maximumTimer.set_exception(TimeoutError(errorMessage))

            self._timeout_timer = self._loop.create_task(
                _timeout_func())  # noqa: E501
        else:
            self._timeout_timer = self._loop.create_future()
        return self._maximumTimer

    def _navigatedWithinDocument(self, frame: Frame = None):
        if frame != self._frame:
            return
        self._hasSameDocumentNavigation = True
        self._checkLifecycleComplete()

    def _checkLifecycleComplete(self, frame: Frame = None):
        if not self._checkLifecycle(self._frame, self._expectedLifecycle):
            return
        if not self._lifecyclePromise.done():
            self._lifecyclePromise.set_result(None)
        if self._frame._loaderId == self._initialLoaderId and not self._hasSameDocumentNavigation:
            return
        if self._hasSameDocumentNavigation and not self._sameDocumentNavigationPromise.done():
            self._sameDocumentNavigationPromise.set_result(None)
        if self._frame._loaderId != self._initialLoaderId and not self._newDocumentNavigationPromise.done():
            self._newDocumentNavigationPromise.set_result(None)

    def dispose(self):
        self._maximumTimer.cancel()
        self._timeout_timer.cancel()
        helper.removeEventListeners(self._eventListeners)

    @property
    def lifecyclePromise(self):
        return self._lifecyclePromise

    @property
    def newDocumentNavigationPromise(self):
        return self._newDocumentNavigationPromise

    @property
    def sameDocumentNavigationPromise(self):
        return self._sameDocumentNavigationPromise


pyppeteerToProtocolLifecycle = {
    'load': 'load',
    'domcontentloaded': 'DOMContentLoaded',
    'documentloaded': 'DOMContentLoaded',
    'networkAlmostIdle': 'networkAlmostIdle',
    'networkidle0': 'networkIdle',
    'networkidle2': 'networkAlmostIdle',
}
