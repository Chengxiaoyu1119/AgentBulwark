"""Bounded fan-out for modern MCP ``subscriptions/listen`` streams."""

from __future__ import annotations

import queue
import threading
import weakref
from dataclasses import dataclass, field
from time import monotonic
from typing import Any, Callable, Generator
from uuid import uuid4

from apps.api.agent_supervisor.mcp_gateway.config import gateway_max_subscriptions
from apps.api.agent_supervisor.mcp_gateway.http_transport import (
    build_subscription_acknowledgement,
    encode_sse_message,
    normalize_subscription_filter,
    project_subscription_notification,
)

_POLL_INTERVAL_SECONDS = 0.1
_KEEPALIVE_SECONDS = 15.0
_QUEUE_SIZE = 200


class SubscriptionCapacityError(ValueError):
    """Raised before SSE headers when the global subscription budget is full."""


@dataclass
class _Subscriber:
    subscription_id: Any
    agreed_filter: dict[str, Any]
    messages: queue.Queue[dict[str, Any] | None] = field(default_factory=lambda: queue.Queue(maxsize=_QUEUE_SIZE))


class _ScopeWorker:
    def __init__(
        self,
        gateway: Any,
        agent_id: str,
        session_id: str,
        on_failure: Callable[["_ScopeWorker", int], None],
        on_subscriber_closed: Callable[["_ScopeWorker", str, bool], None],
    ) -> None:
        self.gateway = gateway
        self.agent_id = agent_id
        self.session_id = session_id
        self.on_failure = on_failure
        self.on_subscriber_closed = on_subscriber_closed
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.subscribers: dict[str, _Subscriber] = {}
        self.thread = threading.Thread(target=self._run, daemon=True, name="mcp-subscription-dispatch")

    def start(self) -> None:
        self.thread.start()

    def add(self, subscriber: _Subscriber) -> str:
        token = uuid4().hex
        with self.lock:
            self.subscribers[token] = subscriber
        return token

    def remove(self, token: str) -> tuple[bool, bool]:
        with self.lock:
            removed = token in self.subscribers
            self.subscribers.pop(token, None)
            empty = not self.subscribers
        if empty:
            self.stop_event.set()
        return removed, empty

    def close(self) -> int:
        self.stop_event.set()
        with self.lock:
            subscribers = list(self.subscribers.values())
            self.subscribers.clear()
        for subscriber in subscribers:
            _close_queue(subscriber.messages)
        return len(subscribers)

    def _run(self) -> None:
        while not self.stop_event.wait(_POLL_INTERVAL_SECONDS):
            try:
                notifications = self.gateway.notifications(
                    agent_id=self.agent_id,
                    session_id=self.session_id,
                )
            except Exception:  # noqa: BLE001 - a broken upstream closes streams without leaking details
                closed_count = self.close()
                self.on_failure(self, closed_count)
                return
            if not notifications:
                continue
            with self.lock:
                subscribers = list(self.subscribers.items())
            for notification in notifications:
                if not isinstance(notification, dict):
                    continue
                for token, subscriber in subscribers:
                    with self.lock:
                        if token not in self.subscribers:
                            continue
                    projected = project_subscription_notification(
                        notification,
                        subscriber.agreed_filter,
                        subscriber.subscription_id,
                    )
                    if projected is None:
                        continue
                    try:
                        subscriber.messages.put_nowait(projected)
                    except queue.Full:
                        # Disconnect a slow consumer instead of silently losing
                        # security-relevant change notifications or growing RAM.
                        _close_queue(subscriber.messages)
                        removed, empty = self.remove(token)
                        if removed:
                            self.on_subscriber_closed(self, token, empty)


class SubscriptionBroker:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._scopes: dict[tuple[int, str, str], _ScopeWorker] = {}
        self._subscriber_count = 0

    def subscribe(
        self,
        gateway: Any,
        *,
        agent_id: str,
        session_id: str,
        subscription_id: Any,
        agreed_filter: dict[str, Any],
    ) -> tuple[_Subscriber, tuple[int, str, str], str]:
        scope = (id(gateway), agent_id, session_id)
        with self._lock:
            maximum = gateway_max_subscriptions()
            if self._subscriber_count >= maximum:
                raise SubscriptionCapacityError(f"MCP 活动订阅已达到 {maximum} 条上限。")
            worker = self._scopes.get(scope)
            created = worker is None
            if worker is None:
                gateway.pin_session(agent_id=agent_id, session_id=session_id)

                def handle_failure(failed: _ScopeWorker, count: int) -> None:
                    self._worker_failed(scope, failed, count)

                def handle_subscriber_closed(failed: _ScopeWorker, token: str, empty: bool) -> None:
                    self._subscriber_closed(scope, failed, token, empty)

                worker = _ScopeWorker(
                    gateway,
                    agent_id,
                    session_id,
                    handle_failure,
                    handle_subscriber_closed,
                )
                self._scopes[scope] = worker
            subscriber = _Subscriber(subscription_id=subscription_id, agreed_filter=agreed_filter)
            token = worker.add(subscriber)
            self._subscriber_count += 1
            if created:
                try:
                    worker.start()
                except BaseException:
                    worker.close()
                    self._scopes.pop(scope, None)
                    self._subscriber_count = max(0, self._subscriber_count - 1)
                    gateway.unpin_session(agent_id=agent_id, session_id=session_id)
                    raise
        return subscriber, scope, token

    def unsubscribe(self, scope: tuple[int, str, str], token: str) -> None:
        with self._lock:
            worker = self._scopes.get(scope)
            if worker is None:
                return
            removed, empty = worker.remove(token)
            if not removed:
                return
            self._subscriber_count = max(0, self._subscriber_count - 1)
            if empty:
                self._scopes.pop(scope, None)
                worker.gateway.unpin_session(agent_id=worker.agent_id, session_id=worker.session_id)

    def reset(self) -> None:
        with self._lock:
            workers = list(self._scopes.values())
            self._scopes.clear()
            self._subscriber_count = 0
        for worker in workers:
            worker.close()
            worker.gateway.unpin_session(agent_id=worker.agent_id, session_id=worker.session_id)

    def _worker_failed(
        self,
        scope: tuple[int, str, str],
        worker: _ScopeWorker,
        closed_count: int,
    ) -> None:
        with self._lock:
            if self._scopes.get(scope) is not worker:
                return
            self._scopes.pop(scope, None)
            self._subscriber_count = max(0, self._subscriber_count - closed_count)
        worker.gateway.unpin_session(agent_id=worker.agent_id, session_id=worker.session_id)

    def _subscriber_closed(
        self,
        scope: tuple[int, str, str],
        worker: _ScopeWorker,
        token: str,
        empty: bool,
    ) -> None:
        """Release capacity immediately when a slow consumer is evicted."""

        del token  # The worker has already removed the token from its map.
        should_unpin = False
        with self._lock:
            if self._scopes.get(scope) is not worker:
                return
            self._subscriber_count = max(0, self._subscriber_count - 1)
            if empty:
                self._scopes.pop(scope, None)
                should_unpin = True
        if should_unpin:
            worker.gateway.unpin_session(agent_id=worker.agent_id, session_id=worker.session_id)

    def has_active(self, gateway: Any, *, agent_id: str | None = None, session_id: str | None = None) -> bool:
        gateway_id = id(gateway)
        with self._lock:
            return any(
                scope_gateway == gateway_id
                and (agent_id is None or scope_agent == agent_id)
                and (session_id is None or scope_session == session_id)
                for scope_gateway, scope_agent, scope_session in self._scopes
            )


_BROKER = SubscriptionBroker()


def stream_modern_subscription(
    gateway: Any,
    *,
    agent_id: str,
    session_id: str,
    subscription_id: Any,
    params: dict[str, Any],
) -> Generator[str, None, None]:
    agreed_filter = normalize_subscription_filter(params)
    subscriber, scope, token = _BROKER.subscribe(
        gateway,
        agent_id=agent_id,
        session_id=session_id,
        subscription_id=subscription_id,
        agreed_filter=agreed_filter,
    )
    # Subscription creation deliberately happens before returning the nested
    # iterator. FastAPI therefore has not committed SSE response headers when
    # capacity or session-pinning fails, and the route can return structured
    # JSON instead of a broken 200 stream.
    def generate() -> Generator[str, None, None]:
        try:
            # The acknowledgement is unconditionally first, even if the worker
            # observes a change while this generator is being scheduled.
            yield encode_sse_message(
                build_subscription_acknowledgement(
                    subscription_id,
                    agreed_filter,
                    server_name=str(getattr(gateway, "server_name", "") or ""),
                    server_version=str(getattr(gateway, "server_version", "") or ""),
                )
            )
            last_output = monotonic()
            while True:
                timeout = max(0.1, _KEEPALIVE_SECONDS - (monotonic() - last_output))
                try:
                    message = subscriber.messages.get(timeout=timeout)
                except queue.Empty:
                    last_output = monotonic()
                    yield ": keepalive\n\n"
                    continue
                if message is None:
                    return
                last_output = monotonic()
                yield encode_sse_message(message)
        finally:
            _BROKER.unsubscribe(scope, token)

    stream = generate()
    # FastAPI normally starts iterating immediately, but a request may be
    # rejected or abandoned after ``StreamingResponse`` construction and
    # before iteration begins.  A generator's ``finally`` block does not run
    # when an unstarted generator is merely discarded, so attach an independent
    # GC finalizer to prevent a leaked subscriber/session lease in that edge
    # case.  ``unsubscribe`` is idempotent for an already-closed stream.
    weakref.finalize(stream, _BROKER.unsubscribe, scope, token)
    return stream


def reset_subscription_broker() -> None:
    _BROKER.reset()


def modern_subscription_active(
    gateway: Any,
    *,
    agent_id: str | None = None,
    session_id: str | None = None,
) -> bool:
    return _BROKER.has_active(gateway, agent_id=agent_id, session_id=session_id)


def _close_queue(messages: queue.Queue[dict[str, Any] | None]) -> None:
    try:
        while True:
            messages.get_nowait()
    except queue.Empty:
        pass
    try:
        messages.put_nowait(None)
    except queue.Full:
        pass
