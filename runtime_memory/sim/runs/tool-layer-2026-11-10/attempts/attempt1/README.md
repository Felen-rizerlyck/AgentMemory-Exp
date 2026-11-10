# attempt1 (superseded)

First run of the harness. C3 failed because the harness expected a decision-record key `action`; the record uses `decision`. D5 used port 1 and timed out instead of refusing. These were test-harness issues, not tool-layer implementation changes. The final run under `../../` uses the corrected harness.
