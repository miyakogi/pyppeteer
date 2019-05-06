#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Worker module."""

import logging
import functools
from typing import Any, Callable, Dict, List, TYPE_CHECKING

from pyee import AsyncIOEventEmitter

from pyppeteer.execution_context import ExecutionContext, JSHandle
from pyppeteer.helper import debugError

if TYPE_CHECKING:
    from pyppeteer.connection import CDPSession  # noqa: F401

logger = logging.getLogger(__name__)


class Worker(AsyncIOEventEmitter):
    """The Worker class represents a WebWorker.

    The events `workercreated` and `workerdestroyed` are emitted on the page
    object to signal the worker lifecycle.

    .. code::

        page.on('workercreated', lambda worker: print('Worker created:', worker.url))
    """  # noqa: E501

    def __init__(self, client: 'CDPSession', url: str,  # noqa: C901
                 consoleAPICalled: Callable[[str, List[JSHandle], str], None],
                 exceptionThrown: Callable[[Dict], None]
                 ) -> None:
        super().__init__()
        self._client = client
        self._url = url
        self._loop = client._loop
        self._executionContextPromise = self._loop.create_future()
        jsHandleFactory = lambda remoteObject: remoteObject

        def onExecutionContentCreated(event: Dict) -> None:
            nonlocal jsHandleFactory
            executionContext = ExecutionContext(client, event['context'], None)
            jsHandleFactory = functools.partial(JSHandle,
                                                context=executionContext,
                                                client=client)
            self._executionContextPromise.set_result(executionContext)

        self._client.on('Runtime.executionContextCreated',
                        onExecutionContentCreated)

        try:
            # This might fail if the target is closed before we receive all
            # execution contexts.
            self._client.send('Runtime.enable', {})
        except Exception as e:
            debugError(logger, e)

        def onConsoleAPICalled(event: Dict) -> None:
            consoleAPICalled(event['type'], list(
                map(lambda x: jsHandleFactory(remoteObject=x),
                    event.get('args', []))), event.get('stackTrace'))

        self._client.on('Runtime.consoleAPICalled', onConsoleAPICalled)
        self._client.on(
            'Runtime.exceptionThrown',
            lambda exception: exceptionThrown(exception['exceptionDetails']),
        )

    @property
    def url(self) -> str:
        """Return URL."""
        return self._url

    async def executionContext(self) -> ExecutionContext:
        """Return ExecutionContext."""
        return await self._executionContextPromise

    async def evaluate(self, pageFunction: str, *args: Any) -> Any:
        """Evaluate ``pageFunction`` with ``args``.

        Shortcut for ``(await worker.executionContext).evaluate(pageFunction, *args)``.
        """  # noqa: E501
        return await (await self._executionContextPromise).evaluate(
            pageFunction, *args)

    async def evaluateHandle(self, pageFunction: str, *args: Any) -> JSHandle:
        """Evaluate ``pageFunction`` with ``args`` and return :class:`~pyppeteer.execution_context.JSHandle`.

        Shortcut for ``(await worker.executionContext).evaluateHandle(pageFunction, *args)``.
        """  # noqa: E501
        return await (await self._executionContextPromise).evaluateHandle(
            pageFunction, *args)
