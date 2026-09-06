"""
android_bridge.py

All the Android-specific plumbing, isolated in one file. Uses pyjnius to
call Android's native MediaStore APIs directly from Python.

LIKELY TROUBLE SPOTS (flagging honestly, since these can only really be
verified by running on an actual device):
  - MediaStore column names/behavior differ slightly across Android
    versions (10, 11, 12, 13+). Tested logic here targets API 29+.
  - ContentObserver-based "instant" watching is complex to wire through
    pyjnius reliably, so this uses POLLING instead (checks every few
    seconds while the app is open). Good enough for a foreground app;
    a true background Service is a separate, bigger addition later.
"""

from jnius import autoclass, cast
import io
import hashlib

PythonActivity = autoclass('org.kivy.android.PythonActivity')
ContentValues = autoclass('android.content.ContentValues')
MediaStoreDownloads = autoclass('android.provider.MediaStore$Downloads')
MediaStoreFiles = autoclass('android.provider.MediaStore$Files')
MediaStoreFilesFileColumns = autoclass('android.provider.MediaStore$Files$FileColumns')
MediaStoreMediaColumns = autoclass('android.provider.MediaStore$MediaColumns')
Environment = autoclass('android.os.Environment')


def _get_resolver():
    activity = PythonActivity.mActivity
    return activity.getContentResolver()


def list_downloads():
    """
    Returns a list of dicts for every file currently in the Downloads
    collection: [{"id": int, "name": str, "date_added": int}, ...]
    """
    resolver = _get_resolver()
    collection = MediaStoreDownloads.EXTERNAL_CONTENT_URI
    projection = [
        MediaStoreMediaColumns._ID,
        MediaStoreMediaColumns.DISPLAY_NAME,
        MediaStoreMediaColumns.DATE_ADDED,
    ]

    cursor = resolver.query(collection, projection, None, None, None)
    results = []
    if cursor is not None:
        try:
            id_col = cursor.getColumnIndexOrThrow(MediaStoreMediaColumns._ID)
            name_col = cursor.getColumnIndexOrThrow(MediaStoreMediaColumns.DISPLAY_NAME)
            date_col = cursor.getColumnIndexOrThrow(MediaStoreMediaColumns.DATE_ADDED)
            while cursor.moveToNext():
                results.append({
                    "id": cursor.getLong(id_col),
                    "name": cursor.getString(name_col),
                    "date_added": cursor.getLong(date_col),
                })
        finally:
            cursor.close()
    return results


def get_download_uri(file_id: int):
    """Builds the content:// Uri for a specific download by its id."""
    ContentUris = autoclass('android.content.ContentUris')
    collection = MediaStoreDownloads.EXTERNAL_CONTENT_URI
    return ContentUris.withAppendedId(collection, file_id)


def read_file_bytes(uri) -> bytes:
    """Reads a file's full content (given its content:// Uri) into a
    Python bytes object, so it can be hashed / parsed with pypdf."""
    resolver = _get_resolver()
    input_stream = resolver.openInputStream(uri)
    buffer = io.BytesIO()
    chunk_size = 8192
    java_buf = bytearray(chunk_size)
    try:
        while True:
            n = input_stream.read(java_buf)
            if n == -1:
                break
            buffer.write(bytes(java_buf[:n]))
    finally:
        input_stream.close()
    return buffer.getvalue()


def delete_file(uri):
    """Deletes a file from MediaStore (used for dangerous/duplicate files)."""
    resolver = _get_resolver()
    resolver.delete(uri, None, None)


def save_to_category_folder(source_uri, file_name: str, category: str, subfolder: str = None) -> bool:
    """
    Copies a file (given its source content:// Uri, still in Downloads)
    into Documents/<category>/[<subfolder>/]<file_name>, then removes
    it from Downloads. Returns True on success.
    """
    resolver = _get_resolver()

    relative_path = f"{Environment.DIRECTORY_DOCUMENTS}/{category}"
    if subfolder:
        relative_path += f"/{subfolder}"

    values = ContentValues()
    values.put(MediaStoreFilesFileColumns.DISPLAY_NAME, file_name)
    values.put(MediaStoreFilesFileColumns.RELATIVE_PATH, relative_path)

    collection = MediaStoreFiles.getContentUri("external")
    new_uri = resolver.insert(collection, values)
    if new_uri is None:
        return False

    try:
        in_stream = resolver.openInputStream(source_uri)
        out_stream = resolver.openOutputStream(new_uri)
        chunk_size = 8192
        java_buf = bytearray(chunk_size)
        while True:
            n = in_stream.read(java_buf)
            if n == -1:
                break
            out_stream.write(java_buf, 0, n)
        in_stream.close()
        out_stream.close()

        # Remove the original from Downloads now that it's been copied.
        resolver.delete(source_uri, None, None)
        return True
    except Exception as e:
        print(f"[android_bridge] save_to_category_folder failed: {e}")
        return False


def list_existing_subfolders(category: str):
    """
    Returns a list of subfolder names that already exist under
    Documents/<category>/, by querying distinct RELATIVE_PATH values.
    NOTE: this only sees folders that already contain at least one
    MediaStore-indexed file — an empty folder created outside the app
    won't show up here. This is a real Android/MediaStore limitation.
    """
    resolver = _get_resolver()
    collection = MediaStoreFiles.getContentUri("external")
    projection = [MediaStoreFilesFileColumns.RELATIVE_PATH]
    prefix = f"{Environment.DIRECTORY_DOCUMENTS}/{category}/"

    selection = f"{MediaStoreFilesFileColumns.RELATIVE_PATH} LIKE ?"
    selection_args = [f"{prefix}%"]

    cursor = resolver.query(collection, projection, selection, selection_args, None)
    subfolders = set()
    if cursor is not None:
        try:
            path_col = cursor.getColumnIndexOrThrow(MediaStoreFilesFileColumns.RELATIVE_PATH)
            while cursor.moveToNext():
                full_path = cursor.getString(path_col)
                if full_path and full_path.startswith(prefix):
                    remainder = full_path[len(prefix):].strip("/")
                    if remainder:
                        subfolders.add(remainder.split("/")[0])
        finally:
            cursor.close()
    return list(subfolders)


def compute_hash_from_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
