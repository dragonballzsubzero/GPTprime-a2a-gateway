"""Network-isolated static upload triage worker. Advisory, not a production renderer.
Run only inside provided no-network, read-only, non-root container profile.
"""
import hashlib, io, json, os, stat, sys, zipfile
MAX_BYTES=10*1024*1024
MAX_ZIP_ENTRIES=256
MAX_UNCOMPRESSED=50*1024*1024

def triage(path):
    fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size>MAX_BYTES:
            return {"status":"REJECT","reason":"FILE_TYPE_OR_SIZE"}
        with os.fdopen(fd,"rb",closefd=False) as f:
            data=f.read(MAX_BYTES+1)
        if len(data)>MAX_BYTES:return {"status":"REJECT","reason":"FILE_TOO_LARGE"}
    finally: os.close(fd)
    fmt="binary"
    if data.startswith(b"%PDF-"):fmt="pdf"
    elif data.startswith(b"\x89PNG\r\n\x1a\n"):fmt="png"
    elif data.startswith(b"PK\x03\x04"):fmt="zip"
    else:
        try:data.decode("utf-8");fmt="utf8"
        except UnicodeDecodeError:pass
    result={"status":"ADVISORY_ONLY","format":fmt,"bytes":len(data),
            "sha256":hashlib.sha256(data).hexdigest(),"flags":[]}
    flags=result["flags"]
    if fmt=="pdf":
        for marker in (b"/JavaScript",b"/OpenAction",b"/Launch",b"/EmbeddedFile"):
            if marker.lower() in data.lower():flags.append("PDF_ACTIVE_CONTENT_MARKER")
        if b"/Encrypt" in data: flags.append("PDF_ENCRYPTED_OR_INDICATED")
    if fmt=="zip":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                infos=z.infolist()
                if len(infos)>MAX_ZIP_ENTRIES:return {"status":"REJECT","reason":"ZIP_ENTRY_LIMIT"}
                total=sum(i.file_size for i in infos)
                if total>MAX_UNCOMPRESSED:return {"status":"REJECT","reason":"ZIP_DECLARED_EXPANSION"}
                for i in infos:
                    parts=i.filename.replace("\\","/").split("/")
                    if i.filename.startswith("/") or ".." in parts:
                        return {"status":"REJECT","reason":"ZIP_PATH_TRAVERSAL"}
                    if (i.external_attr>>16)&0o170000==stat.S_IFLNK:
                        return {"status":"REJECT","reason":"ZIP_SYMLINK"}
                    if i.compress_size==0 and i.file_size>0:
                        return {"status":"REJECT","reason":"ZIP_EXTREME_RATIO"}
                    if i.compress_size>0 and i.file_size/i.compress_size>50:
                        return {"status":"REJECT","reason":"ZIP_EXTREME_RATIO"}
        except (zipfile.BadZipFile,ValueError,OverflowError):
            return {"status":"REJECT","reason":"MALFORMED_ZIP"}
    return result

if __name__=="__main__":
    if len(sys.argv)!=2:sys.exit(2)
    try:
        print(json.dumps(triage(sys.argv[1]),sort_keys=True))
    except (OSError,ValueError):
        print(json.dumps({"status":"REJECT","reason":"FILE_READ_OR_PARSE_ERROR"}))
        sys.exit(1)
