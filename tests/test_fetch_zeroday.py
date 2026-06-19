import pandas as pd

from temporal_exploit.fetch import zeroday
from temporal_exploit.fetch.zeroday import COLUMNS, ZerodayConnector, parse_zeroday_csv

SAMPLE = (
    "CVE,Vendor,Product,Type,Description,Date Discovered,Date Patched,Advisory\n"
    "CVE-2021-0001,VendorA,ProductA,RCE,desc,2021-01-05,2021-02-01,http://a\n"
    "notacve,X,Y,Z,d,2020-01-01,2020-02-01,http://b\n"
    "CVE-2021-0001,VendorA,ProductA,RCE,dup,2021-03-05,2021-04-01,http://c\n"
    "CVE-2022-0009,VendorB,ProductB,LPE,desc,???,2022-05-01,http://d\n"
)


def test_parse_filters_dedupes_and_coerces_dates():
    frame = parse_zeroday_csv(SAMPLE)

    assert list(frame.columns) == COLUMNS
    assert set(frame["cve_id"]) == {"CVE-2021-0001", "CVE-2022-0009"}  # non-CVE row dropped
    assert str(frame["zeroday_date_discovered"].dt.tz) == "UTC"

    first = frame.set_index("cve_id").loc["CVE-2021-0001"]
    assert first["zeroday_date_discovered"] == pd.Timestamp("2021-01-05", tz="UTC")  # first dup kept
    assert first["zeroday_vendor"] == "VendorA"

    missing = frame.set_index("cve_id").loc["CVE-2022-0009"]
    assert pd.isna(missing["zeroday_date_discovered"])  # "???" coerced to NaT


def test_connector_fetches_via_seam(monkeypatch):
    monkeypatch.setattr(zeroday, "_fetch_csv", lambda url, cache_dir=None: SAMPLE)
    frame = ZerodayConnector().fetch()
    assert set(frame["cve_id"]) == {"CVE-2021-0001", "CVE-2022-0009"}
    assert ZerodayConnector.name == "google_0day"
