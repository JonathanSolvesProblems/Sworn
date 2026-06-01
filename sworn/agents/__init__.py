"""Multi-agent specialists.

Find Evil! criterion #1 (Autonomous Execution Quality) is the tiebreaker.
SWORN decomposes triage into four specialists so no single LLM context holds
all raw evidence:

  - MemorySpecialist:  Volatility 3 plugins
  - DiskSpecialist:    Sleuth Kit + MFT + plaso + RegRipper + PECmd + Hindsight
  - NetworkSpecialist: bulk_extractor URLs/IPs/emails + Volatility netscan
  - Synthesizer:       reads INDICATIONs from the others, proposes DRAFTs

Each specialist runs as a SpecialistLoop with a self-correction cap. The
Synthesizer is the only specialist allowed to call gateway.submit; the
others stage INDICATION-only observations the Synthesizer corroborates.
"""

from sworn.agents.loop import SpecialistLoop, SelfCorrectionExceeded, Observation
from sworn.agents.specialists import (
    MemorySpecialist,
    DiskSpecialist,
    NetworkSpecialist,
    Synthesizer,
)

__all__ = [
    "SpecialistLoop",
    "SelfCorrectionExceeded",
    "Observation",
    "MemorySpecialist",
    "DiskSpecialist",
    "NetworkSpecialist",
    "Synthesizer",
]
