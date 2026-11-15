"""Copy an intake file to a private staging directory through no-follow FDs."""
import os
import stat
import sys

MAX_BYTES=10*1024*1024


def stage(root, source, destination):
    if not all(os.path.isabs(p) for p in (root,source,destination)):
        raise ValueError('ABSOLUTE_PATHS_REQUIRED')
    relative=os.path.relpath(source,root)
    parts=relative.split(os.sep)
    if not parts or any(p in ('','.', '..') for p in parts):
        raise ValueError('INPUT_OUTSIDE_ROOT')
    nofollow=getattr(os,'O_NOFOLLOW',0)
    if not nofollow or not hasattr(os,'O_DIRECTORY'):
        raise ValueError('NOFOLLOW_REQUIRED')
    current=os.open(root,os.O_RDONLY|os.O_DIRECTORY|nofollow)
    source_fd=None
    try:
        for part in parts[:-1]:
            nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|nofollow,dir_fd=current)
            os.close(current);current=nxt
        source_fd=os.open(parts[-1],os.O_RDONLY|nofollow|getattr(os,'O_NONBLOCK',0),dir_fd=current)
        before=os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>MAX_BYTES:
            raise ValueError('INPUT_TYPE_SIZE_OR_LINK')
        flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|nofollow
        out=os.open(destination,flags,0o600)
        try:
            total=0
            while True:
                data=os.read(source_fd,1024*1024)
                if not data: break
                total+=len(data)
                if total>MAX_BYTES: raise ValueError('INPUT_TOO_LARGE')
                view=memoryview(data)
                while view:
                    count=os.write(out,view)
                    if count<=0: raise OSError('SHORT_WRITE')
                    view=view[count:]
            after=os.fstat(source_fd)
            attrs=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
            if total!=before.st_size or any(getattr(before,a)!=getattr(after,a) for a in attrs):
                raise ValueError('INPUT_CHANGED_WHILE_STAGING')
            os.fchmod(out,0o444)
            os.fsync(out)
        finally:
            os.close(out)
    finally:
        if source_fd is not None: os.close(source_fd)
        os.close(current)


if __name__=='__main__':
    try:
        if len(sys.argv)!=4: raise ValueError('ARGUMENTS_REQUIRED')
        stage(*sys.argv[1:])
    except (OSError,ValueError) as e:
        print('STAGING_REJECTED: '+str(e),file=sys.stderr)
        sys.exit(1)
