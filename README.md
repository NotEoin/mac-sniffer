# probe-sniffer

Counts how many devices are near you by passively listening for 802.11 probe requests.

Phones broadcast probe requests constantly, looking for known networks. Counting the unique source
MACs in those probes gives you a rough headcount of nearby radios — except that since iOS 8 and
Android 8, phones randomise their MAC while probing, so a single phone can look like dozens of
devices over a few minutes.

This handles that by clustering on the probe's **information-element fingerprint** rather than
trusting the MAC.

## The randomisation problem

A probe request carries a set of information elements — supported rates, HT/VHT capabilities,
extended capabilities, and the order they appear in. That combination is a property of the chipset
and driver, not of the address, and it survives MAC rotation.

So the cluster key is:

- **the MAC**, when it looks universally administered (a real OUI), or when the probe carried too
  few IEs to be discriminating;
- **the IE fingerprint**, when the MAC is locally administered — bit 1 of the first octet set, which
  is what randomised addresses look like.

One phone rotating through twenty addresses collapses to one cluster. The floor is that two
identical handsets on the same OS version will fingerprint alike and merge into one — that
undercount is inherent to the technique rather than a bug, and it's why the output is "roughly how
busy is this space", not a census.

Devices count as present if any observation falls inside a sliding window (default 5 minutes). Stale
clusters expire lazily on query.

`--no-fingerprint` falls back to counting raw unique MACs, which is useful mainly for seeing how much
difference the clustering makes. `--exclude-randomized` drops locally-administered MACs entirely, as
a cross-check.

## Install

```bash
./setup.sh
```

Creates the conda environment from `environment.yml`. You need a wireless adapter that supports
monitor mode — many built-in cards don't.

## Use

The interface has to be in monitor mode first:

```bash
sudo ./wlan_setup.sh wlan1        # -> wlan1mon
```

Then:

```bash
sudo python -m probe_sniffer --iface wlan1mon
sudo python -m probe_sniffer --iface wlan1mon --backend pyshark
sudo python -m probe_sniffer --iface wlan1mon --window 600 --interval 30
```

| Flag | Default | Meaning |
|---|---|---|
| `--iface` | required | monitor-mode interface |
| `--backend` | `scapy` | `scapy` or `pyshark` |
| `--interval` | 30 | seconds between count printouts |
| `--window` | 300 | sliding window for "in the vicinity" |
| `--no-fingerprint` | off | count raw MACs instead of clusters |
| `--exclude-randomized` | off | drop locally-administered MACs entirely |

There are two backends because they fail differently: scapy is dependency-light and fine for most
things, pyshark hands off to tshark and parses IEs more thoroughly on unusual frames. Both sit
behind a shared `SnifferBackend` interface, so adding a third is a small job.

## Legal and ethical use

**Read this before pointing it at anything.**

Probe requests are broadcast in the clear and this tool only listens — it never transmits, never
associates, never deauthenticates, and never touches frame payloads. That doesn't make the data
non-personal.

**MAC addresses are personal data** under UK/EU GDPR: they identify a device, and a device usually
identifies a person. The fingerprint clustering here makes that stronger, not weaker — the entire
point of it is to re-identify a device across the randomisation that was introduced specifically to
prevent tracking. Treat the output accordingly.

So:

- Run it on **premises and networks you own**, or where you have explicit permission.
- Don't use it to track individuals, follow a specific device, or build a movement history.
- Don't retain the data. This holds observations in memory in a sliding window and writes nothing to
  disk. Keep it that way unless you have a reason and a lawful basis.
- If you deploy it anywhere the public passes through — a shop, an office, an event — you are
  processing personal data at scale, and you need a lawful basis, a notice, and probably a DPIA.
  "It's only counting" is not a defence.
- Monitor mode and passive capture are lawful in most jurisdictions. **Check yours**, because in some
  they aren't.

I wrote this to answer "how busy is this room" without putting a camera in it. That's the use it's
designed for.

## Licence

MIT — see [LICENSE](LICENSE).
