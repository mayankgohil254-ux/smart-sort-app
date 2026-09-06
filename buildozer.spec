[app]
title = SmartSort
package.name = smartsort
package.domain = org.example
source.dir = .
source.include_exts = py,png,jpg,kv,atlas
version = 0.1
requirements = python3,kivy,pyjnius,pypdf

orientation = portrait
fullscreen = 0

android.permissions = READ_EXTERNAL_STORAGE, WRITE_EXTERNAL_STORAGE, MANAGE_EXTERNAL_STORAGE, POST_NOTIFICATIONS

android.api = 33
android.minapi = 29
android.ndk = 25b
android.accept_sdk_license = True

[buildozer]
log_level = 2
warn_on_root = 1
