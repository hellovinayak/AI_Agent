import asyncio
from queue import Queue
import threading
import logging
from app.models.alert import LogEntry

logger = logging.getLogger(__name__)

class MLAnalysisQueue:
    def __init__(self):
        self.queue = Queue(maxsize=1000)
        self._worker = threading.Thread(target=self._process, daemon=True)
        self._worker.start()
        self._loop = None

    def submit(self, log_entry: LogEntry):
        if self._loop is None:
            try:
                self._loop = asyncio.get_running_loop()
            except RuntimeError:
                pass
        try:
            self.queue.put_nowait(log_entry)
        except Exception:
            pass  # drop under load — log a metric

    def _process(self):
        # We need to import inside the thread to avoid circular imports if any
        from app.services import zero_knowledge_engine
        from app.services.detection_engine import _fire_zero_day_alert
        
        while True:
            log_entry = self.queue.get()
            try:
                # The PyTorch/HDBSCAN synchronous blocking call
                alert = zero_knowledge_engine.analyze_for_zero_day(log_entry)
                if alert and self._loop:
                    # It found a zero-day anomaly! Send it to the detection engine
                    # Run it safely on the main event loop
                    asyncio.run_coroutine_threadsafe(
                        _fire_zero_day_alert(log_entry, alert),
                        self._loop
                    )
            except Exception as e:
                logger.error(f'ML worker error: {e}')

ml_queue = MLAnalysisQueue()
