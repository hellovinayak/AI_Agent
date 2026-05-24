import time
from collections import deque

class IngestionHealthMonitor:
    def __init__(self):
        self._event_timestamps = deque(maxlen=1000)
        self._processing_times = deque(maxlen=100)
        self._dropped_events = 0
        self._total_events = 0
        self._last_event_time = time.time()
        self._websocket_connected = True
        self._llm_available = True

    def record_event(self, processing_time_ms: float):
        now = time.time()
        self._event_timestamps.append(now)
        self._processing_times.append(processing_time_ms)
        self._total_events += 1
        self._last_event_time = now

    def record_dropped(self):
        self._dropped_events += 1
        self._total_events += 1

    def compute_health(self) -> dict:
        now = time.time()

        # Events per second (last 10 seconds)
        recent = [t for t in self._event_timestamps if now - t < 10]
        events_per_second = len(recent) / 10

        # Drop rate
        drop_rate = (self._dropped_events / max(self._total_events, 1)) * 100

        # Processing latency
        avg_latency = (sum(self._processing_times) /
                       max(len(self._processing_times), 1))

        # Time since last event (seconds)
        silence_seconds = now - self._last_event_time

        # Component scores
        throughput_score = min(100, (events_per_second / 10) * 100)
        drop_score = max(0, 100 - (drop_rate * 10))
        latency_score = max(0, 100 - (avg_latency / 10))
        freshness_score = max(0, 100 - (silence_seconds * 5))
        ws_score = 100 if self._websocket_connected else 0
        llm_score = 100 if self._llm_available else 60  # degraded not dead

        # Weighted composite
        health = (
            throughput_score * 0.30 +
            drop_score       * 0.25 +
            latency_score    * 0.20 +
            freshness_score  * 0.15 +
            ws_score         * 0.05 +
            llm_score        * 0.05
        )

        return {
            'health_pct': round(health, 1),
            'status': self._health_label(health),
            'events_per_second': round(events_per_second, 1),
            'avg_latency_ms': round(avg_latency, 1),
            'drop_rate_pct': round(drop_rate, 2),
            'websocket_connected': self._websocket_connected,
            'llm_available': self._llm_available,
            'silence_seconds': round(silence_seconds, 1),
            'total_processed': self._total_events
        }

    def _health_label(self, score: float) -> str:
        if score >= 95: return 'OPTIMAL'
        if score >= 80: return 'DEGRADED'
        if score >= 60: return 'WARNING'
        return 'CRITICAL'

# Singleton — instantiate once and pass around
health_monitor = IngestionHealthMonitor()
