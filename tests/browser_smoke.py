
"""Exercise a running Sentinel-SOC app from Chromium."""
import json
import sys
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

URL = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8501").rstrip("/")
DEMO = Path(__file__).resolve().parents[1] / "samples" / "synthetic_logins.csv"


def choose(page, label, option):
    page.get_by_test_id("stSelectbox").filter(has_text=label).get_by_role("combobox").click()
    page.get_by_role("option", name=option, exact=False).click()


def main():
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        context = browser.new_context(accept_downloads=True, service_workers="block")
        external = []

        def local_only(route):
            if route.request.url.startswith(URL + "/"):
                route.continue_()
            else:
                external.append(route.request.url)
                route.abort()

        context.route("**/*", local_only)
        page = context.new_page()
        page.goto(URL)
        expect(page.get_by_text("Load the synthetic demo or upload", exact=False)).to_be_visible()
        page.get_by_role("button", name="Load synthetic demo").click()
        expect(page.get_by_role("heading", name="Alert queue")).to_be_visible()
        choose(page, "Select incident", "casey /")
        expect(page.get_by_role("heading", name="Evidence timeline")).to_be_visible()
        expect(page.get_by_text("source rows 7, 4, 9", exact=False)).to_be_visible()
        expect(page.get_by_text("source row 2", exact=False)).to_be_visible()
        choose(page, "Incident status", "Investigating")
        expect(page.get_by_role("combobox", name="Selected Investigating. Incident status")).to_be_visible()
        expect(page.get_by_text("Running...", exact=True)).to_be_hidden()
        choose(page, "Select incident", "devon /")
        expect(page.get_by_text("source rows 3, 8, 6", exact=False)).to_be_visible()
        choose(page, "Select incident", "casey /")
        expect(page.get_by_test_id("stSelectbox").filter(has_text="Incident status")).to_contain_text("Investigating")
        expect(page.get_by_text("Running...", exact=True)).to_be_hidden()
        with page.expect_download() as downloaded:
            page.get_by_role("button", name="Download incident JSON").click()
        payload = json.loads(downloaded.value.path().read_text(encoding="utf-8"))
        assert payload["status"] == "Investigating", payload
        assert payload["matching_row_ids"] == [7, 4, 9, 2], payload
        assert [event["row"] for event in payload["evidence"]] == [7, 4, 9, 2], payload
        assert all(event["timestamp"].endswith("Z") for event in payload["evidence"])
        assert payload["detection_settings"] == {"threshold": 3, "failure_minutes": 10, "success_minutes": 15}
        print("PASS: demo, alert selection, cited evidence, status persistence, JSON download and inspection")

        upload = page.locator('input[type="file"]')
        upload.set_input_files(DEMO)
        page.get_by_role("button", name="Analyze CSV").click()
        expect(page.get_by_text("Uploaded CSV", exact=True)).to_be_visible()
        expect(page.get_by_role("heading", name="Alert queue")).to_be_visible()
        upload.set_input_files({"name": "bad.csv", "mimeType": "text/csv", "buffer": b"wrong,header\nx,y"})
        page.get_by_role("button", name="Analyze CSV").click()
        expect(page.get_by_text("Use unique CSV headers", exact=False)).to_be_visible()
        assert not external, external
        print("PASS: normal CSV upload, invalid upload, and no external page requests")
        browser.close()


if __name__ == "__main__":
    main()
