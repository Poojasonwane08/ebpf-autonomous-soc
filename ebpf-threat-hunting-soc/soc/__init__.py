"""eBPF-Powered Autonomous Threat Hunting SOC.

Pipeline:  eBPF sensor (Tetragon / simulator)  ->  Kafka  ->  normalizer
           ->  CEP / detection engine (Sigma + behavioural + anomaly)
           ->  SOAR playbooks  ->  response actions back to the sensors
           ->  dashboard + forensic evidence.
"""

__version__ = "1.0.0"
