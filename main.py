"""
main.py

The actual Android app. Polls Downloads every few seconds (while the app
is open), runs the same security + category logic we built and tested
on Windows, and shows real popups instead of terminal y/n prompts.

Run/build this with Buildozer (see buildozer.spec).

KNOWN LIMITATION (being upfront): this only watches while the app is
open in the foreground. A background Service that watches even when
the app is closed is a bigger, separate addition — this gets the core
logic working on Android first.
"""

import os
import re
import json

from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.popup import Popup
from kivy.uix.scrollview import ScrollView
from kivy.clock import Clock

import android_bridge

# ============================================================
# Same category/keyword logic as the Windows version — ported
# directly, no Android-specific changes needed here.
# ============================================================
CATEGORIES = {
    "Study": [
        "assignment", "syllabus", "lecture", "notes", "chapter",
        "university", "college", "exam", "study guide", "homework",
        "thesis", "course", "semester", "textbook", "quiz", "worksheet",
        "admit card", "hall ticket", "result", "prompt engineering", "ai"
    ],
    "Personal": [
        "passport", "aadhar", "aadhaar", "id card", "birth certificate",
        "family", "photo id", "marksheet"
    ],
    "Financial": [
        "bank statement", "invoice", "receipt", "salary", "payslip",
        "tax", "loan", "credit card", "transaction"
    ],
    "Medical": [
        "prescription", "diagnosis", "hospital", "medical report",
        "insurance", "lab report", "vaccination"
    ],
    "Legal": [
        "contract", "agreement", "affidavit", "notarized", "court",
        "legal notice", "terms and conditions"
    ],
    "Work": [
        "resume", "cv", "offer letter", "appointment letter",
        "project report", "meeting minutes", "appraisal"
    ],
    "Travel": [
        "boarding pass", "itinerary", "visa", "hotel booking",
        "flight ticket", "reservation"
    ],
}

CODE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".c", ".cpp", ".h", ".hpp",
    ".cs", ".php", ".rb", ".go", ".rs", ".swift", ".kt", ".html", ".css",
    ".json", ".sql", ".sh", ".xml", ".yaml", ".yml", ".dart"
}
VIDEO_EXTENSIONS = {".mkv", ".mp4", ".avi", ".mov", ".wmv", ".webm", ".m4v"}

STRONG_MATCH_THRESHOLD = 7

MAGIC_NUMBERS = {
    ".pdf": [b"%PDF-"],
    ".png": [b"\x89PNG\r\n\x1a\n"],
    ".jpg": [b"\xff\xd8\xff"],
    ".jpeg": [b"\xff\xd8\xff"],
    ".zip": [b"PK\x03\x04"],
    ".docx": [b"PK\x03\x04"],
    ".apk": [b"PK\x03\x04"],
}


def _get_seen_hashes_path() -> str:
    """App's own private storage — no special permission needed here."""
    app = App.get_running_app()
    base_dir = app.user_data_dir if app else "/data/data/org.example.smartsort/files"
    return os.path.join(base_dir, "seen_hashes.json")


# ============================================================
# Security check (adapted to work on in-memory bytes, since
# Android files are accessed via content:// Uris, not plain paths)
# ============================================================
def check_file_bytes(data: bytes, file_name: str) -> dict:
    reasons = []
    is_safe = True

    _, ext = os.path.splitext(file_name.lower())
    expected = MAGIC_NUMBERS.get(ext)
    if expected:
        header = data[:1024]
        matched = any(header.startswith(sig) for sig in expected)
        if not matched:
            is_safe = False
            reasons.append(f"SIGNATURE MISMATCH: '{file_name}' claims to be {ext} "
                            f"but its content doesn't match a real {ext} file.")
        elif ext == ".pdf" and b"%%EOF" not in data[-1024:]:
            is_safe = False
            reasons.append("PDF is missing its end-of-file marker (possibly corrupted/truncated).")

    file_hash = android_bridge.compute_hash_from_bytes(data)
    duplicate_of = _get_previous_hash_entry(file_hash)
    if duplicate_of:
        reasons.append(f"Duplicate of a previously saved file: {duplicate_of}")
    _remember_hash(file_hash, file_name)

    if ext == ".pdf" and is_safe:
        embedded = _check_embedded_attachments(data)
        if embedded:
            is_safe = False
            reasons.append(f"EMBEDDED FILES FOUND inside PDF: {', '.join(embedded)}")
        if b"/Launch" in data:
            is_safe = False
            reasons.append("AUTO-LAUNCH ACTION FOUND in this PDF.")

    if not reasons:
        reasons.append("No problems found.")

    return {"safe": is_safe, "reasons": reasons, "file_hash": file_hash, "duplicate_of": duplicate_of}


def _check_embedded_attachments(data: bytes) -> list:
    try:
        from pypdf import PdfReader
        import io
        reader = PdfReader(io.BytesIO(data))
        if reader.attachments:
            return list(reader.attachments.keys())
    except Exception:
        pass
    return []


def _load_seen_hashes() -> dict:
    path = _get_seen_hashes_path()
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def _get_previous_hash_entry(file_hash: str):
    seen = _load_seen_hashes()
    return seen.get(file_hash)


def _remember_hash(file_hash: str, file_name: str):
    seen = _load_seen_hashes()
    seen[file_hash] = file_name
    path = _get_seen_hashes_path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(seen, f)
    except OSError:
        pass


# ============================================================
# Category detection (same scoring logic as Windows version)
# ============================================================
def analyze_file(data: bytes, file_name: str):
    file_name_lower = file_name.lower()
    _, ext = os.path.splitext(file_name_lower)

    if ext in CODE_EXTENSIONS:
        return [("Coding", 1)], ""
    if ext in VIDEO_EXTENSIONS:
        return [("Movie", 1)], ""

    text = ""
    if ext == ".pdf":
        text = _extract_pdf_text(data)

    combined = file_name_lower.replace("_", " ").replace("-", " ") + " " + text.lower()

    scores = []
    for category, keywords in CATEGORIES.items():
        hits = sum(1 for kw in keywords if kw in combined)
        if hits > 0:
            scores.append((category, hits))
    scores.sort(key=lambda pair: pair[1], reverse=True)
    return scores, combined


def _extract_pdf_text(data: bytes, max_chars: int = 2000) -> str:
    try:
        from pypdf import PdfReader
        import io
        reader = PdfReader(io.BytesIO(data))
        if len(reader.pages) > 0:
            return (reader.pages[0].extract_text() or "")[:max_chars]
    except Exception:
        pass
    return ""


# ============================================================
# The Kivy App itself
# ============================================================
class SmartSortApp(App):
    def build(self):
        self.log_label = Label(text="Starting...", size_hint_y=None, halign="left", valign="top")
        self.log_label.bind(texture_size=self.log_label.setter('size'))

        scroll = ScrollView()
        scroll.add_widget(self.log_label)

        root = BoxLayout(orientation="vertical")
        start_button = Button(text="Start Watching Downloads", size_hint_y=None, height=60)
        start_button.bind(on_press=self.start_watching)
        root.add_widget(start_button)
        root.add_widget(scroll)

        self.seen_ids = set()
        self.watching = False

        return root

    def log(self, message: str):
        self.log_label.text += f"\n{message}"
        print(message)

    def start_watching(self, instance):
        if self.watching:
            return
        self.watching = True
        # Record what's already there so we only react to NEW files.
        self.seen_ids = {f["id"] for f in android_bridge.list_downloads()}
        self.log("Watching Downloads for new files...")
        Clock.schedule_interval(self.check_for_new_downloads, 5)

    def check_for_new_downloads(self, dt):
        current = android_bridge.list_downloads()
        for entry in current:
            if entry["id"] not in self.seen_ids:
                self.seen_ids.add(entry["id"])
                self.handle_new_file(entry)

    def handle_new_file(self, entry):
        file_id = entry["id"]
        file_name = entry["name"]
        self.log(f"\nNew file detected: {file_name}")

        uri = android_bridge.get_download_uri(file_id)
        try:
            data = android_bridge.read_file_bytes(uri)
        except Exception as e:
            self.log(f"[ERROR] Could not read file: {e}")
            return

        result = check_file_bytes(data, file_name)

        if not result["safe"]:
            self.log(f"WARNING - DANGEROUS: {file_name}")
            for reason in result["reasons"]:
                self.log(f"  - {reason}")
            self.show_delete_popup(uri, file_name)
            return

        self.log(f"Safe: {file_name}")
        if result["duplicate_of"]:
            self.log(f"  (note) Duplicate — old copy tracked as: {result['duplicate_of']}")
            # NOTE: deleting the OLD file by name alone isn't reliable via
            # MediaStore (need its own Uri, not just filename). This is a
            # known simplification — a full fix means storing the Uri/id
            # per hash instead of just the filename.

        matches, combined_text = analyze_file(data, file_name)

        if not matches:
            self.log("  No category matched — leaving in Downloads.")
            return

        top_category, top_score = matches[0]

        if top_category in ("Coding", "Movie") or top_score >= STRONG_MATCH_THRESHOLD:
            self.log(f"  Auto-routing to: {top_category}")
            self.move_file(uri, file_name, top_category)
            return

        self.show_category_popup(uri, file_name, top_category, top_score)

    def show_delete_popup(self, uri, file_name):
        layout = BoxLayout(orientation="vertical", spacing=10, padding=10)
        layout.add_widget(Label(text=f"'{file_name}' looks dangerous.\nDelete it?"))

        buttons = BoxLayout(size_hint_y=None, height=50, spacing=10)
        popup = Popup(title="Dangerous File", content=layout, size_hint=(0.8, 0.4))

        def on_delete(instance):
            android_bridge.delete_file(uri)
            self.log(f"[DELETED] {file_name}")
            popup.dismiss()

        def on_keep(instance):
            self.log(f"Kept '{file_name}' in Downloads, not sorted.")
            popup.dismiss()

        delete_btn = Button(text="Delete")
        delete_btn.bind(on_press=on_delete)
        keep_btn = Button(text="Keep")
        keep_btn.bind(on_press=on_keep)
        buttons.add_widget(delete_btn)
        buttons.add_widget(keep_btn)
        layout.add_widget(buttons)

        popup.open()

    def show_category_popup(self, uri, file_name, category, score):
        layout = BoxLayout(orientation="vertical", spacing=10, padding=10)
        layout.add_widget(Label(text=f"'{file_name}'\nmatched {score} keyword(s) for '{category}'."))

        buttons = BoxLayout(size_hint_y=None, height=50, spacing=10)
        popup = Popup(title="Choose Folder", content=layout, size_hint=(0.8, 0.4))

        def on_category(instance):
            self.move_file(uri, file_name, category)
            popup.dismiss()

        def on_downloads(instance):
            self.log(f"Kept '{file_name}' in Downloads.")
            popup.dismiss()

        cat_btn = Button(text=category)
        cat_btn.bind(on_press=on_category)
        downloads_btn = Button(text="Downloads")
        downloads_btn.bind(on_press=on_downloads)
        buttons.add_widget(cat_btn)
        buttons.add_widget(downloads_btn)
        layout.add_widget(buttons)

        popup.open()

    def move_file(self, uri, file_name, category):
        success = android_bridge.save_to_category_folder(uri, file_name, category)
        if success:
            self.log(f"[MOVED] '{file_name}' -> Documents/{category}")
        else:
            self.log(f"[ERROR] Could not move '{file_name}'")


if __name__ == "__main__":
    SmartSortApp().run()
