"""Message bus abstraction.

* ``MemoryBus`` - in-process pub/sub, used when running everything in one
  Python process (no Docker needed, ideal for a Windows laptop).
* ``KafkaBus``  - Apache Kafka via confluent-kafka, used by the Docker stack.

Both expose the same tiny API so every service is bus-agnostic::

    bus.publish(topic, dict, key=None)
    bus.subscribe([topics], handler, group="service-name")
"""
from __future__ import annotations

import json
import logging
import queue
import threading
import time
from collections import defaultdict
from typing import Callable, Iterable

from . import config

log = logging.getLogger("soc.bus")
Handler = Callable[[str, dict], None]


class Bus:
    def publish(self, topic: str, message: dict, key: str | None = None) -> None:
        raise NotImplementedError

    def subscribe(self, topics: Iterable[str], handler: Handler, group: str) -> None:
        raise NotImplementedError

    def close(self) -> None:
        pass


class MemoryBus(Bus):
    """Thread-based pub/sub. Each subscriber gets its own queue + worker thread,
    so a slow consumer never blocks a producer (same semantics as Kafka consumer
    groups with one partition)."""

    def __init__(self) -> None:
        self._subs: dict[str, list[queue.Queue]] = defaultdict(list)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self.published = defaultdict(int)
        self._queues: list[queue.Queue] = []

    def publish(self, topic, message, key=None):
        self.published[topic] += 1
        with self._lock:
            subs = list(self._subs.get(topic, []))
        for q in subs:
            q.put((topic, message))

    def subscribe(self, topics, handler, group):
        q: queue.Queue = queue.Queue()
        with self._lock:
            for t in topics:
                self._subs[t].append(q)

        def worker():
            while not self._stop.is_set():
                try:
                    topic, msg = q.get(timeout=0.2)
                except queue.Empty:
                    continue
                try:
                    handler(topic, msg)
                except Exception:  # never kill the consumer thread
                    log.exception("handler error in %s", group)
                finally:
                    q.task_done()

        threading.Thread(target=worker, name=f"sub-{group}", daemon=True).start()
        self._queues.append(q)

    def drain(self, timeout: float = 10.0) -> None:
        """Block until every subscriber queue is empty (used by tests)."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if all(q.unfinished_tasks == 0 for q in self._queues):
                time.sleep(0.05)
                if all(q.unfinished_tasks == 0 for q in self._queues):
                    return
            time.sleep(0.02)

    def close(self):
        self._stop.set()


class KafkaBus(Bus):
    def __init__(self, bootstrap: str | None = None) -> None:
        from confluent_kafka import Producer
        from confluent_kafka.admin import AdminClient, NewTopic

        self.bootstrap = bootstrap or config.KAFKA_BOOTSTRAP
        self._stop = threading.Event()

        # Wait for the broker and make sure every topic exists.
        admin = AdminClient({"bootstrap.servers": self.bootstrap})
        for attempt in range(60):
            try:
                existing = set(admin.list_topics(timeout=5).topics)
                missing = [t for t in config.ALL_TOPICS if t not in existing]
                if missing:
                    futures = admin.create_topics(
                        [NewTopic(t, num_partitions=3, replication_factor=1) for t in missing])
                    for t, f in futures.items():
                        try:
                            f.result()
                        except Exception as exc:  # already exists (race between services)
                            log.debug("create topic %s: %s", t, exc)
                break
            except Exception as exc:
                log.info("waiting for Kafka at %s (%s)", self.bootstrap, exc)
                time.sleep(2)
        else:
            raise RuntimeError(f"Kafka not reachable at {self.bootstrap}")

        self._producer = Producer({
            "bootstrap.servers": self.bootstrap,
            "linger.ms": 5,
            "compression.type": "lz4",
            "queue.buffering.max.messages": 500000,
        })
        threading.Thread(target=self._poll_loop, daemon=True).start()
        log.info("connected to Kafka at %s", self.bootstrap)

    def _poll_loop(self):
        while not self._stop.is_set():
            self._producer.poll(0.1)

    def publish(self, topic, message, key=None):
        data = json.dumps(message, default=str).encode()
        while True:
            try:
                self._producer.produce(topic, data, key=key.encode() if key else None)
                return
            except BufferError:
                self._producer.poll(0.05)

    def subscribe(self, topics, handler, group):
        from confluent_kafka import Consumer

        consumer = Consumer({
            "bootstrap.servers": self.bootstrap,
            "group.id": group,
            "auto.offset.reset": "latest",
            "enable.auto.commit": True,
        })
        consumer.subscribe(list(topics))

        def worker():
            while not self._stop.is_set():
                msg = consumer.poll(0.5)
                if msg is None:
                    continue
                if msg.error():
                    log.debug("kafka error: %s", msg.error())
                    continue
                try:
                    handler(msg.topic(), json.loads(msg.value()))
                except Exception:
                    log.exception("handler error in %s", group)
            consumer.close()

        threading.Thread(target=worker, name=f"kafka-{group}", daemon=True).start()

    def close(self):
        self._producer.flush(5)
        self._stop.set()


def create_bus(kind: str | None = None) -> Bus:
    kind = (kind or config.BUS).lower()
    if kind == "kafka":
        return KafkaBus()
    return MemoryBus()
