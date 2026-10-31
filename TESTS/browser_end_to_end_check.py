"""Full end-to-end check through a REAL browser.

Starts the real server and two real client agents (two simulated TPMs = two PCs),
opens the chat GUI in Chromium with a virtual Windows Hello, and walks through the
demo: register, chat, block, evade with a new account (TPM auto-block), review,
and new-PC login (UC-06).

    pip install playwright && playwright install chromium
    python TESTS/browser_end_to_end_check.py [--screenshots DIR]
"""
import argparse
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parent.parent
PYTHON = sys.executable
SERVER_PORT = 8100


def wait_for(url, seconds=30):
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=1)
            return
        except Exception:
            time.sleep(0.3)
    raise RuntimeError(f"{url} did not come up")


def start_processes(workdir):
    env = dict(os.environ, PIM_DATABASE_PATH=str(Path(workdir) / "e2e.sqlite3"), PIM_DEMO_SHOW_OTP="1",
               PIM_SIMULATED_TPM_DIR=str(Path(workdir) / "tpm"), PYTHONUNBUFFERED="1")
    processes = [subprocess.Popen([PYTHON, str(ROOT / "SERVER" / "run_server.py"), "--host", "127.0.0.1",
                                   "--port", str(SERVER_PORT)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)]
    wait_for(f"http://127.0.0.1:{SERVER_PORT}/health")
    for name, port in (("PC-1", 8765), ("PC-2", 8766), ("PC-3", 8767)):
        processes.append(subprocess.Popen(
            [PYTHON, str(ROOT / "CLIENT" / "run_client.py"), "--server", f"http://127.0.0.1:{SERVER_PORT}", "--tpm",
             "simulated", "--tpm-name", name, "--port", str(port), "--no-browser"],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE))
        wait_for(f"http://localhost:{port}/agent/status")
    return processes


def new_pc_page(browser, port):
    """One browser profile = one PC, with its own virtual Windows Hello."""
    context = browser.new_context()
    page = context.new_page()
    page.on("dialog", lambda dialog: dialog.accept())
    page.on("pageerror", lambda error: print("   [browser error]", error))
    page.goto(f"http://localhost:{port}/")
    cdp = context.new_cdp_session(page)
    cdp.send("WebAuthn.enable")
    cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
        "protocol": "ctap2", "transport": "internal", "hasResidentKey": True, "hasUserVerification": True,
        "isUserVerified": True, "automaticPresenceSimulation": True}})
    return page


def register(page, username, email, phone):
    page.click("[data-goto=register]")
    page.fill("#reg-username", username)
    page.fill("#reg-password", "Correct-horse-7")
    page.fill("#reg-email", email)
    page.fill("#reg-phone", phone)
    page.click("#panel-register button[type=submit]")
    enter_codes(page)
    page.click("#hello-button")
    expect(page.locator("#chat-view")).to_be_visible()
    expect(page.locator("#me-name")).to_have_text("@" + username)


def enter_codes(page):
    expect(page.locator("#otp-demo")).to_be_visible()
    codes = re.findall(r"code (\d{6}), phone code (\d{6})", page.inner_text("#otp-demo"))[0]
    page.fill("#otp-email", codes[0])
    page.fill("#otp-phone", codes[1])
    page.click("#panel-otp button[type=submit]")
    expect(page.locator("#panel-hello")).to_be_visible()


def login(page, username):
    page.fill("#login-username", username)
    page.fill("#login-password", "Correct-horse-7")
    page.click("#panel-login button[type=submit]")


def logout(page):
    page.click("#logout-button")
    expect(page.locator("#auth-view")).to_be_visible()


def open_chat_with(page, peer):
    page.fill("#search-input", peer[:3])
    page.locator("#search-results div", has_text="@" + peer).click()
    expect(page.locator("#thread-title")).to_have_text("@" + peer)


def send(page, text):
    page.fill("#composer-input", text)
    page.click("#composer button[type=submit]")


def step(message):
    print(f"  ✔ {message}", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--screenshots", help="folder to save screenshots in")
    arguments = parser.parse_args()
    shots = Path(arguments.screenshots) if arguments.screenshots else None
    if shots:
        shots.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as workdir:
        processes = start_processes(workdir)
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch()
                pc1 = new_pc_page(browser, 8765)     # USER1's PC
                pc2 = new_pc_page(browser, 8766)     # USER2's PC
                print("Browser end-to-end check")

                register(pc1, "alice", "alice@gmail.com", "+91 98765 00001")
                step("USER1 registered on PC-1 (OTP + Windows Hello)")
                register(pc2, "bob", "bob@gmail.com", "+91 98765 00002")
                step("USER2 registered on PC-2 (OTP + Windows Hello)")

                open_chat_with(pc2, "alice")
                send(pc2, "Hi Alice, it's Bob")
                expect(pc1.locator("#tab-chats .item", has_text="@bob")).to_be_visible(timeout=8000)
                pc1.locator("#tab-chats .item", has_text="@bob").click()
                expect(pc1.locator(".bubble", has_text="Hi Alice, it's Bob")).to_be_visible()
                send(pc1, "Hi Bob!")
                expect(pc2.locator(".bubble", has_text="Hi Bob!")).to_be_visible(timeout=8000)
                step("messages travel between the two PCs in both directions")
                if shots:
                    pc1.screenshot(path=str(shots / "1_chat_alice.png"))

                pc1.click("#thread-actions button.danger")
                expect(pc1.locator("#empty-state")).to_be_visible()      # the conversation closes after blocking
                pc1.click("[data-tab=blocked]")
                expect(pc1.locator("#tab-blocked .card", has_text="@bob")).to_be_visible(timeout=8000)
                step("USER1 blocked USER2 (UC-03)")
                send(pc2, "are you there?")
                expect(pc2.locator("#empty-state")).to_be_visible(timeout=8000)    # thread vanished: user not found
                step("USER2 now sees USER1 as 'user not found' (UC-05)")

                logout(pc2)
                register(pc2, "bob_again", "totally.new@gmail.com", "+91 98765 00003")
                pc2.fill("#search-input", "ali")
                pc2.wait_for_timeout(800)
                expect(pc2.locator("#search-results")).to_contain_text("No users found")
                step("USER2 made a NEW account (new e-mail, new phone) on the same PC: still cannot find USER1")

                pc1.click("[data-tab=review]")
                expect(pc1.locator("#tab-review .card", has_text="@bob_again")).to_be_visible(timeout=8000)
                expect(pc1.locator("#tab-review")).to_contain_text("same TPM-verified PC")
                step("Policy Engine auto-blocked the new account via the TPM link (UC-04); USER1 sees it in Review (UC-07)")
                if shots:
                    pc1.screenshot(path=str(shots / "2_review_alice.png"))

                pc1.locator("#tab-review .card", has_text="@bob_again").get_by_role("button").click()
                expect(pc1.locator("#tab-review")).not_to_contain_text("@bob_again", timeout=8000)
                step("USER1 marked the new account 'not the same person' and unblocked only that one (UC-07/UC-08)")

                # --- family PC (soft block): ravi and priya share PC-3 BEFORE alice blocks ravi
                pc3 = new_pc_page(browser, 8767)
                register(pc3, "ravi", "ravi@gmail.com", "+91 98765 00010")
                logout(pc3)
                register(pc3, "priya", "priya@gmail.com", "+91 98765 00010")      # same family phone, own Gmail
                pc1.click("[data-tab=chats]")
                open_chat_with(pc1, "ravi")
                pc1.click("#thread-actions button.danger")
                pc1.click("[data-tab=review]")
                expect(pc1.locator("#tab-review .card.soft", has_text="@priya")).to_be_visible(timeout=8000)
                step("alice blocked ravi; priya (same family PC) is NOT blocked, but alice is asked (soft block)")
                open_chat_with(pc3, "alice")
                send(pc3, "Hello Alice, this is Priya, not Ravi")
                pc3.wait_for_timeout(500)
                expect(pc3.locator(".bubble", has_text="this is Priya")).to_be_visible()          # priya sees a normal 'sent'
                expect(pc1.locator("#tab-review .card.soft")).to_contain_text("1 held message", timeout=8000)
                step("priya's message looks delivered to her, but is held back from alice until she decides")
                if shots:
                    pc1.screenshot(path=str(shots / "2b_soft_block_alice.png"))
                pc1.locator("#tab-review .card.soft", has_text="@priya").get_by_role("button", name="Allow").click()
                pc1.click("[data-tab=chats]")
                pc1.locator("#tab-chats .item", has_text="@priya").click()
                expect(pc1.locator(".bubble", has_text="this is Priya")).to_be_visible(timeout=8000)
                step("alice pressed Allow: the held message is delivered and priya can chat normally")

                logout(pc1)
                logout(pc2)
                login(pc2, "alice")                                   # USER1's account, but on PC-2: unknown PC
                expect(pc2.locator("#panel-otp")).to_be_visible()
                step("login to alice's account from a NEW PC stops at the OTP check (UC-06)")
                enter_codes(pc2)
                pc2.click("#hello-button")                           # register Windows Hello for the new PC
                expect(pc2.locator("#panel-hello")).to_contain_text("now linked")
                pc2.click("#hello-button")                           # sign in with it
                expect(pc2.locator("#me-name")).to_have_text("@alice")
                step("new PC enrolled (OTP + new Windows Hello credential) and logged in (UC-06)")
                if shots:
                    pc2.screenshot(path=str(shots / "3_new_device_alice.png"))
                browser.close()
            print("\nALL BROWSER CHECKS PASSED")
        finally:
            for process in processes:
                process.terminate()
            for process in processes:
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()


if __name__ == "__main__":
    main()
