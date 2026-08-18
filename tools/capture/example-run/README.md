# The capture behind the README figure

The run `media/live-capture.png` is drawn from, kept so the figure can be redrawn without a wireless
card:

```bash
python tools/plot_capture.py \
    tools/capture/example-run/clustered.log \
    tools/capture/example-run/raw.log \
    --plan "pinned to 2437 MHz" --out media/live-capture.png
```

Both logs cover the same fifteen minutes of the same room, captured at once by two sniffers sharing
one monitor interface — `clustered.log` counting devices, `raw.log` started with `--no-fingerprint`
so it counts addresses. The figure is the comparison between them.

They hold interval reports and nothing else: counts, and the times they were printed. No address,
network name or anything else identifying a device is ever written to a log, which is why these can
be published where a raw capture could not.

Each log ends with a scapy socket warning and a `capture ended unexpectedly` line. That is the
capture script taking the interface back down at the end of the run. `plot_capture.py` ignores them.

`run-meta.txt` covers the whole session, which is why it says `runs=both` — the session also
recorded a channel-hopping run, and only the pinned one is kept here.
