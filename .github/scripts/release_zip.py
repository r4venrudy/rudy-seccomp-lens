"""Read ZIP framing before handing the archive to the standard decoder."""
import zipfile


def open_zip(stream):
    stream.seek(0, 2)
    size = stream.tell()
    # Use the same classic/ZIP64 interpretation as ZipFile.
    footer = zipfile._EndRecData(stream)
    if footer is None:
        raise zipfile.BadZipFile("missing ZIP end record")
    if footer[zipfile._ECD_LOCATION] + zipfile.sizeEndCentDir + footer[zipfile._ECD_COMMENT_SIZE] != size:
        raise ValueError("ZIP footer extent disagrees with file size")
    return zipfile.ZipFile(stream)
