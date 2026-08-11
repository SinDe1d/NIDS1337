from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock

from .detector import Detector
from .features import FeatureExtractor
from .flows import Flow
from .storage import Storage


@dataclass
class PipelineConfig:
    threshold: float = 0.65
    ignored_ips: set[str] = field(default_factory=set)
    ignored_ports: set[int] = field(default_factory=set)


class DetectionPipeline:
    def __init__(self, storage: Storage, model_path: str = "models/nids_model.joblib"):
        self.storage = storage
        self.detector = Detector(model_path)
        self.features = FeatureExtractor()
        self.config = PipelineConfig(threshold=self.detector.threshold)
        self.lock = Lock()

    def process_flow(self, flow: Flow) -> dict:
        features = self.features.extract(flow)
        flow_id = self.storage.add_flow(flow, features)
        ignored = (
            flow.src_ip in self.config.ignored_ips
            or flow.dst_ip in self.config.ignored_ips
            or flow.src_port in self.config.ignored_ports
            or flow.dst_port in self.config.ignored_ports
        )
        if ignored:
            return {"flow_id": flow_id, "alert": None, "ignored": True}
        self.detector.threshold = self.config.threshold
        attack_type, confidence, reason = self.detector.predict(flow, features)
        alert = None
        if attack_type:
            alert_id = self.storage.add_alert(flow, attack_type, confidence, reason, flow_id)
            alert = {
                "id": alert_id, "attack_type": attack_type,
                "confidence": confidence, "reason": reason, "flow_id": flow_id,
            }
        return {"flow_id": flow_id, "alert": alert, "ignored": False}
