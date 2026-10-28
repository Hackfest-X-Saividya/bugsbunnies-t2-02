from zeroshadow_security.upload_formats import (
    CONFIGURATION,
    DEPENDENCY_MANIFEST,
    PROJECT_ARCHIVE,
    SOURCE,
    SUPPLEMENTAL_DOCUMENT,
    UNSUPPORTED,
    classify_filename,
)


def test_classifies_source_and_supplemental_uploads():
    assert classify_filename("app.py") == SOURCE
    assert classify_filename("client.tsx") == SOURCE
    assert classify_filename("project.zip") == PROJECT_ARCHIVE
    assert classify_filename("settings.yaml") == CONFIGURATION
    assert classify_filename("Dockerfile") == CONFIGURATION
    assert classify_filename(".env.example") == CONFIGURATION
    assert classify_filename("requirements.txt") == DEPENDENCY_MANIFEST
    assert classify_filename("package-lock.json") == DEPENDENCY_MANIFEST
    assert classify_filename("SDGRD TF3.txt") == SUPPLEMENTAL_DOCUMENT
    assert classify_filename("secrets.env") == UNSUPPORTED
    assert classify_filename("README.md") == UNSUPPORTED
