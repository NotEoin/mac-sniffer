# 📡 probe-sniffer

![licence](https://img.shields.io/badge/licence-MIT-blue?style=flat-square)
![platform](https://img.shields.io/badge/platform-Linux-lightgrey?style=flat-square)
![python](https://img.shields.io/badge/python-3.10+-blue?style=flat-square)

> *How many people are in this room? Ask their phones.*

Estimate how many devices are nearby by passively listening for the WiFi probe requests phones
broadcast — and get a useful number back even though modern phones randomise their MAC address
specifically to prevent this.

![Raw MAC count climbs; the clustered device count stays flat](./media/clustering.png)

*Thirty minutes of simulated traffic: 12 handsets, 267 distinct MAC addresses, 8 counted devices.
The counts come from this repository's own tracker — only the probe stream is synthetic, since the
alternative is publishing a capture of other people's phones. The gap between 8 and the 11 phones
actually present is the same-chipset collision described below, visible rather than hidden.*

## 🌟 Highlights

- **Counts devices, not addresses.** One phone rotating through twenty MACs is counted once.
- **Completely passive.** It only listens — never transmits, never associates, never deauthenticates
  and never touches packet contents.
- **No app, no camera, no cooperation needed** from the devices being counted.
- **A sliding window** so the number reflects who's here now, not everyone who's walked past.
- **Two capture backends** behind one interface — scapy by default, pyshark available as a
  cross-check.
- **Nothing is stored.** Observations live in memory and are never written to disk.

## ℹ️ Overview

Phones constantly broadcast **probe requests** looking for networks they know. Those broadcasts are
unencrypted and include a sender address, so counting distinct senders gives you a rough headcount
of the radios nearby.

The complication is that since iOS 8 and Android 8, phones use a **randomised address** when probing
and rotate it regularly. Count raw MAC addresses and the number climbs forever, whether or not
anyone new arrived.

**The fix is to key on something that can't be randomised.** A probe request carries a set of
*information elements* — supported rates, capability flags, and the order they appear in. That
combination is a property of the chipset and driver rather than the address, and it survives
rotation. So:

- If the address looks **real** (a genuine manufacturer prefix), key on the MAC.
- If the address looks **randomised**, key on the IE fingerprint instead.

One phone cycling through twenty addresses collapses to a single device.

**The known trade-off:** two identical handsets on the same OS version fingerprint the same and
merge into one. That undercount is inherent to the approach, which is why this gives you *roughly
how busy a space is* rather than an exact count.

### ✍️ Author

Built by [@NotEoin](https://github.com/NotEoin). 

## 🚀 Usage

Put your adapter into monitor mode, then start counting:

```bash
sudo ./setup.sh up wlan1                          # -> wlan1mon
sudo python -m probe_sniffer --iface wlan1mon
```

```
probe-sniffer started on wlan1mon via scapy (window=300s, interval=30s, fingerprint-clustering).
Press Ctrl-C to stop.

[19:42:00] devices in vicinity (last 300s): 14  (universal=3, randomized=11, macs-seen=61)  [unique-ever=73]
[19:42:30] devices in vicinity (last 300s): 15  (universal=3, randomized=12, macs-seen=73)  [unique-ever=86]
[19:43:00] devices in vicinity (last 300s): 14  (universal=3, randomized=11, macs-seen=88)  [unique-ever=101]
```

`macs-seen` climbing while the device count holds steady is the clustering doing its job. When
you're finished, `sudo ./setup.sh down wlan1mon` restores managed mode.

| Flag | Default | What it does |
|---|---|---|
| `--iface` | *required* | Your monitor-mode interface |
| `--interval` | `30` | Seconds between count printouts |
| `--window` | `300` | How long a device counts as "here" after being seen |
| `--backend` | `scapy` | `scapy` or `pyshark` |
| `--no-fingerprint` | off | Count raw MACs instead — useful for comparison |
| `--exclude-randomized` | off | Ignore randomised addresses entirely |

Compare clustered against raw counting to see the difference for yourself:

```bash
sudo python -m probe_sniffer --iface wlan1mon --no-fingerprint
```

## ⬇️ Installation

```bash
git clone https://github.com/NotEoin/mac-sniffer.git
cd mac-sniffer
conda env create -f environment.yml
conda activate probe-sniffer
```

`setup.sh` is not an installer — it's the monitor-mode helper used above, and needs `aircrack-ng`
and `iw`:

```bash
sudo apt install aircrack-ng iw     # Debian/Ubuntu
sudo ./setup.sh list                # show wireless interfaces and their modes
```

**Requirements:**

| | |
|---|---|
| **OS** | Linux |
| **Hardware** | A wireless adapter that supports **monitor mode** — many built-in cards don't |
| **Python** | 3.11 via the conda environment in `environment.yml`; 3.10+ works if you install `scapy` yourself |
| **System** | `aircrack-ng` and `iw`, for `setup.sh` |
| **Permissions** | Root, for packet capture |
| **Optional** | Wireshark/`tshark` for the pyshark backend |

## ⚖️ Legal and ethical use

**Please read this before you run it.**

Probe requests are broadcast in the clear and this tool only listens. That does not make the data
harmless.

**MAC addresses are personal data** under UK and EU GDPR — they identify a device, and a device
usually identifies a person. The fingerprint clustering here makes that stronger, not weaker: its
whole purpose is re-identifying a device across the randomisation designed to prevent exactly that.

- Run it on **premises and networks you own**, or where you have explicit permission.
- **Never** use it to track an individual, follow a specific device, or build a movement history.
- Don't add persistence without a lawful basis. It deliberately writes nothing to disk.
- If you deploy it anywhere the public passes through, you are processing personal data at scale —
  you need a lawful basis, a privacy notice and most likely a DPIA. "It's only a count" is not a
  defence.
- Monitor mode and passive capture are lawful in most places. **Check yours.**

## 🧭 Limitations

- **It's an estimate.** Identical devices merge; devices with WiFi off are invisible.
- **Terminal only** — no persistence, no time series, no dashboard.
- **Accuracy is unvalidated** against a known headcount over a long period. It's clearly better than
  raw MAC counting; how much better is an open question.
- Requires monitor-mode-capable hardware, which rules out most laptops without a USB adapter.

## 💭 Feedback and contributing

Especially interested in accuracy data if you validate it against a real headcount — open an
[issue](https://github.com/NotEoin/mac-sniffer/issues) or start a
[discussion](https://github.com/NotEoin/mac-sniffer/discussions).

## 📄 Licence

MIT — see [LICENSE](LICENSE).
