import unittest
import pandas as pd
from detectors.failed_login_detector import FailedLoginDetector

class TestFailedLoginDetector(unittest.TestCase):
    
    def setUp(self):
        # Create a sample DataFrame for testing
        self.data = {
            'timestamp': ['2024-08-25 00:00:00', '2024-08-25 01:00:00', '2024-08-25 02:00:00'],
            'event_id': [4625, 4625, 4625]  # All failed login events
        }
        self.df = pd.DataFrame(self.data)
        self.detector = FailedLoginDetector(threshold=1, time_window='1h', contamination=0.01)

    def test_threshold_based_detection(self):
        detected = self.detector.threshold_based_detection()
        self.assertGreater(len(detected), 0)

    def test_z_score_analysis(self):
        detected = self.detector.z_score_analysis()
        self.assertGreater(len(detected), 0)

    def test_moving_average_analysis(self):
        detected = self.detector.moving_average_analysis()
        self.assertGreater(len(detected), 0)

    def test_isolation_forest_detection(self):
        detected = self.detector.isolation_forest_detection()
        self.assertGreater(len(detected), 0)

    def test_one_class_svm_detection(self):
        detected = self.detector.one_class_svm_detection()
        self.assertGreater(len(detected), 0)

if __name__ == "__main__":
    unittest.main()
