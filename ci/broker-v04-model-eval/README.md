# Bounded live-model smoke evaluation

`evaluate.py` runs two fixed synthetic instructions with a pinned public model and CPU inference. `exercise.mjs` submits parseable output to the actual broker core with newly generated local test keys, fake authentication, a signed test audit and an in-memory effect. A separate fixed unsafe action verifies the broker's deny path even if the model emits malformed text. Never treat that fixed case as model output.

This is not a provider endpoint test, a real owner approval, a real database effect or an evaluation of GPTPrime or an enrolled node. The model's inability to emit a valid action is a measured result, not a reason to substitute an action. The run consumes bounded external compute; record the actual job and model revision with the result.
