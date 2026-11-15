import {constants} from 'node:fs';
import {open} from 'node:fs/promises';
import path from 'node:path';

/** Linux private-file reader. OS isolation and managed key custody remain external gates. */
export async function readPrivateFile(filePath){
  if(typeof filePath!=='string'||!path.isAbsolute(filePath)||typeof process.getuid!=='function')
    throw new Error('PRIVATE_FILE_PATH_INVALID');
  const file=await open(filePath,constants.O_RDONLY|constants.O_NOFOLLOW);
  try{
    const s=await file.stat();
    if(!s.isFile()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o077)!==0||s.size<1||s.size>65536)
      throw new Error('PRIVATE_FILE_UNSAFE');
    const contents=await file.readFile();
    if(contents.length!==s.size||contents.length>65536)throw new Error('PRIVATE_FILE_CHANGED');
    return new TextDecoder('utf-8',{fatal:true}).decode(contents);
  }finally{await file.close();}
}
