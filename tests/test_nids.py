import tempfile
import unittest
from pathlib import Path

from nids.features import FEATURE_NAMES, FeatureExtractor
from nids.flows import FlowTable
from nids.rules import RuleEngine


class NidsTests(unittest.TestCase):
    def test_reverse_packets_share_flow_and_features_are_zero_safe(self):
        table = FlowTable()
        table.add_packet("a", "b", 10, 20, 6, 60, 1.0, 2)
        flow = table.add_packet("b", "a", 20, 10, 6, 50, 1.1, 18)
        self.assertEqual(flow.total_packets(), 2)
        self.assertEqual(flow.forward_packets, 1)
        self.assertEqual(flow.backward_packets, 1)
        features = FeatureExtractor().extract(flow)
        self.assertEqual(len(features), 28)
        self.assertEqual(set(features), set(FEATURE_NAMES))
        self.assertTrue(all(value == value for value in features.values()))

    def test_syn_flood_rule(self):
        table = FlowTable()
        rule_engine = RuleEngine()
        attack_type = None
        for index in range(6):
            flow = table.add_packet("attacker", "victim", 4000 + index, 80, 6, 60, index, 2)
            attack_type, confidence, _ = rule_engine.inspect(flow)
        self.assertIsNone(attack_type)
        for index in range(10):
            flow = table.add_packet("attacker", "victim", 5000 + index, 80, 6, 60, 10 + index, 2)
            attack_type, confidence, _ = rule_engine.inspect(flow)
        self.assertEqual(attack_type, "SYN flood")
        self.assertGreater(confidence, 0.9)


if __name__ == "__main__":
    unittest.main()
