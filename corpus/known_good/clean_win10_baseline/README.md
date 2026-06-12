# corpus/known_good/clean_win10_baseline

Negative-control image. SWORN must produce zero DRAFT and zero APPROVED findings against this baseline. Any non-zero count is a false positive and is reported in [ACCURACY.md](../../../ACCURACY.md).

## What this is

A vanilla Windows 10 install, fresh from an installer ISO, with no third-party software, no user activity beyond first-login wizard, and no compromise. Used to measure SWORN's silence rate: the fraction of clean baselines on which the agent correctly refuses to flag anything.

## How to obtain

Two acceptable sources (pick whichever is faster on the day):

1. **Build it from scratch (most reproducible).** Spin a Windows 10 22H2 install in VirtualBox or VMware, run through the OOBE, log in once, shut down. Use FTK Imager or `dd` to dump the disk. Approx. 30 GB free space needed.
2. **Use a published clean Win10 image.** SANS DFIR community has shared neutral baselines in the past. Check the Protocol SIFT Slack `#case-data` channel.

Whatever the source, put the resulting `disk.E01` here and update `ground_truth.json` with the actual SHA-256.

## Files in this directory

- `README.md`: this file
- `ground_truth.json`: declares zero artifacts (negative control). See template in this folder.
- `download.sh`: optional, set on the day to fetch the image and verify its hash

Do not commit the actual `disk.E01` file. It is too large and `.gitignore` excludes it.
