"""Check that the shards ran every test that was listed for them.

ci.yml's jobs `test` and `out of reach` run this with the count that the
job "count the tests" listed from the archive, and the folder into which
each shard's JUnit report was downloaded (one folder for each shard). It
fails unless the count is a number above 0 and the reports' tests, added
up, come to it.

    python3 .github/count-runs.py <listed> <folder>
"""

import pathlib
import sys
import xml.etree.ElementTree as ET


def main() -> int:
    listed, folder = sys.argv[1], pathlib.Path(sys.argv[2])
    reports = sorted(folder.glob("*/junit.xml"))
    ran = 0
    for report in reports:
        tests = int(ET.parse(report).getroot().get("tests", "0"))
        print(f"{report.parent.name}: {tests} tests run")
        ran += tests
    print(f"listed: {listed or 'none'}; run, in {len(reports)} reports: {ran}")
    if not listed.isdigit() or int(listed) == 0:
        print("the count of the tests listed is missing")
        return 1
    if ran != int(listed):
        print("the shards did not run every test listed")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
