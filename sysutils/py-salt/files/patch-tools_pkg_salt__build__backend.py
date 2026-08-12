--- tools/pkg/salt_build_backend.py.orig
+++ tools/pkg/salt_build_backend.py
@@ -7,11 +7,6 @@
     sys.path.insert(0, PROJECT_ROOT)

 from setuptools import build_meta as _orig
-from setuptools.build_meta import build_editable as setuptools_build_editable
-from setuptools.build_meta import (
-    prepare_metadata_for_build_editable as setuptools_prepare_metadata,
-)
-
 try:
     from setuptools.build_meta import build_editable as setuptools_build_editable
 except ImportError:
