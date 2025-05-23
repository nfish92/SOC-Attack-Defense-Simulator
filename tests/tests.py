import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from attack_simulator.attack_simulator import AttackSimulator
from defense_simulator.defense_simulator import DefenseSimulator
from logger.logger import EventLogger

def test_attack_generation():
    sim = AttackSimulator()
    logs = sim.generate_realistic_log(10)
    assert "attack_logs" in logs and isinstance(logs["attack_logs"], list)
    assert "defense_logs" in logs and isinstance(logs["defense_logs"], list)
    print(f"[✓] Generated {len(logs['attack_logs'])} attack events.")

def test_field_coverage():
    sim = AttackSimulator()
    event = sim.generate_attack_event()
    required_keys = ["timestamp", "attack_type", "source_ip", "destination_ip", "persona", "is_true_positive", "is_logged"]
    for key in required_keys:
        assert key in event, f"Missing field: {key}"
    print("[✓] Attack event contains all required fields.")

def test_defense_mapping():
    atk = AttackSimulator().generate_attack_event()
    def_event = DefenseSimulator().defend_event(atk)
    assert "defense_action" in def_event
    assert def_event["defense_timestamp"] is None or isinstance(def_event["defense_timestamp"], str)
    print("[✓] Defense response mapped correctly to attack.")

def test_logger_write_and_read():
    logger = EventLogger(log_format="jsonl", echo_console=False)
    atk = AttackSimulator().generate_attack_event()
    def_event = DefenseSimulator().defend_event(atk)
    logger.log_attack(atk)
    logger.log_defense(def_event)
    atk_log = logger.load_log_replay("attack")
    def_log = logger.load_log_replay("defense")
    assert isinstance(atk_log, list) and isinstance(def_log, list)
    print("[✓] Logger wrote and loaded logs successfully.")

if __name__ == "__main__":
    test_attack_generation()
    test_field_coverage()
    test_defense_mapping()
    test_logger_write_and_read()
    print("\nAll tests completed successfully.")
