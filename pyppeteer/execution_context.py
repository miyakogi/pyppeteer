#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Execution Context Module."""

import logging
import math
import re
from typing import Any, Dict, Optional, TYPE_CHECKING

from pyppeteer import helper
from pyppeteer.connection import CDPSession
from pyppeteer.jshandle import createJSHandle, JSHandle
from pyppeteer.errors import ElementHandleError, NetworkError


if TYPE_CHECKING:
    from pyppeteer.frame_manager import Frame  # noqa: F401

logger = logging.getLogger(__name__)

EVALUATION_SCRIPT_URL = '__pyppeteer_evaluation_script__'
SOURCE_URL_REGEX = re.compile(
    r'^[\040\t]*//[@#] sourceURL=\s*(\S*?)\s*$',
    re.MULTILINE,
)


class ExecutionContext(object):
    """Execution Context class."""

    def __init__(self, client: CDPSession, contextPayload: Dict,
                 frame: 'Frame' = None) -> None:
        self._client = client
        self._frame = frame
        self._contextId = contextPayload.get('id')

        auxData = contextPayload.get('auxData', {'isDefault': True})
        self._frameId = auxData.get('frameId', None)
        self._isDefault = bool(auxData.get('isDefault'))

    @property
    def frame(self) -> Optional['Frame']:
        """Return frame associated with this execution context."""
        return self._frame

    async def evaluate(self, pageFunction: str, *args: Any,
                       force_expr: bool = False) -> Any:
        """Execute ``pageFunction`` on this context.

        Details see :meth:`pyppeteer.page.Page.evaluate`.
        """
        handle = await self.evaluateHandle(
            pageFunction, *args, force_expr=force_expr)
        try:
            result = await handle.jsonValue()
        except NetworkError as e:
            if 'Object reference chain is too long' in e.args[0]:
                return
            if 'Object couldn\'t be returned by value' in e.args[0]:
                return
            raise
        await handle.dispose()
        return result

    async def evaluateHandle(self, pageFunction: str, *args: Any,  # noqa: C901
                             force_expr: bool = False) -> 'JSHandle':
        """Execute ``pageFunction`` on this context.

        Details see :meth:`pyppeteer.page.Page.evaluateHandle`.
        """
        suffix = f'//# sourceURL={EVALUATION_SCRIPT_URL}'

        if force_expr or (not args and not helper.is_jsfunc(pageFunction)):
            try:
                if SOURCE_URL_REGEX.match(pageFunction):
                    expressionWithSourceUrl = pageFunction
                else:
                    expressionWithSourceUrl = f'{pageFunction}\n{suffix}'
                _obj = await self._client.send('Runtime.evaluate', {
                    'expression': expressionWithSourceUrl,
                    'contextId': self._contextId,
                    'returnByValue': False,
                    'awaitPromise': True,
                    'userGesture': True,
                })
            except Exception as e:
                _rewriteError(e)

            exceptionDetails = _obj.get('exceptionDetails')
            if exceptionDetails:
                raise ElementHandleError(
                    'Evaluation failed: {}'.format(
                        helper.getExceptionMessage(exceptionDetails)))
            remoteObject = _obj.get('result')
            return createJSHandle(self, remoteObject)

        try:
            _obj = await self._client.send('Runtime.callFunctionOn', {
                'functionDeclaration': f'{pageFunction}\n{suffix}\n',
                'executionContextId': self._contextId,
                'arguments': [self._convertArgument(arg) for arg in args],
                'returnByValue': False,
                'awaitPromise': True,
                'userGesture': True,
            })
        except Exception as e:
            _rewriteError(e)

        exceptionDetails = _obj.get('exceptionDetails')
        if exceptionDetails:
            raise ElementHandleError('Evaluation failed: {}'.format(
                helper.getExceptionMessage(exceptionDetails)))
        remoteObject = _obj.get('result')
        return createJSHandle(self, remoteObject)

    def _convertArgument(self, arg: Any) -> Dict:  # noqa: C901
        if arg == math.inf:
            return {'unserializableValue': 'Infinity'}
        if arg == -math.inf:
            return {'unserializableValue': '-Infinity'}
        objectHandle = arg if isinstance(arg, JSHandle) else None
        if objectHandle:
            if objectHandle._context != self:
                raise ElementHandleError(
                    'JSHandles can be evaluated only in the context they were created!')  # noqa: E501
            if objectHandle._disposed:
                raise ElementHandleError('JSHandle is disposed!')
            if objectHandle._remoteObject.get('unserializableValue'):
                return {'unserializableValue': objectHandle._remoteObject.get(
                    'unserializableValue')}  # noqa: E501
            if not objectHandle._remoteObject.get('objectId'):
                return {'value': objectHandle._remoteObject.get('value')}
            return {'objectId': objectHandle._remoteObject.get('objectId')}
        return {'value': arg}

    async def queryObjects(self, prototypeHandle: 'JSHandle') -> 'JSHandle':
        """Send query.

        Details see :meth:`pyppeteer.page.Page.queryObjects`.
        """
        if prototypeHandle._disposed:
            raise ElementHandleError('Prototype JSHandle is disposed!')
        if not prototypeHandle._remoteObject.get('objectId'):
            raise ElementHandleError(
                'Prototype JSHandle must not be referencing primitive value')
        response = await self._client.send('Runtime.queryObjects', {
            'prototypeObjectId': prototypeHandle._remoteObject['objectId'],
        })
        return createJSHandle(self, response.get('objects'))


def _rewriteError(error: Exception) -> None:
    if error.args[0].endswith('Cannot find context with specified id'):
        msg = 'Execution context was destroyed, most likely because of a navigation.'  # noqa: E501
        raise type(error)(msg)
    raise error
