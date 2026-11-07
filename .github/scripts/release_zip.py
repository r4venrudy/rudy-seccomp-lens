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
    count = footer[zipfile._ECD_ENTRIES_TOTAL]
    if footer[zipfile._ECD_DISK_NUMBER] or footer[zipfile._ECD_DISK_START] or footer[zipfile._ECD_ENTRIES_THIS_DISK] != count:
        raise ValueError("ZIP disk or entry count is inconsistent")
    archive = zipfile.ZipFile(stream)
    if len(archive.infolist()) != count:
        archive.close()
        raise ValueError("ZIP directory entry count disagrees with footer")
    return archive
