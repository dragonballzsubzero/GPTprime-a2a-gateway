#!/usr/bin/env python3
"""Read-only cross-runtime SAC v0.34 Ed25519 verifier for Python 3.13+.

Only authenticates bytes under a supplied trust store. No inference, enrollment,
consensus, or hardware attestation is established by a successful result.
Requires cryptography>=43 (tested locally with 46.0.4).
"""
import base64
import hashlib
import json
import re
import sys
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature

PROTOCOL = 'SAC-A2A-TRANSPORT-1'
VERSION = '0.34'
REQ_KEYS = {'protocol','version','sender','recipient','message_id','nonce','issued_at_ms','expires_at_ms','operation','payload_b64url','signature_b64url'}
RCPT_KEYS = {'protocol','version','node_id','request_sha256','result_sha256','status','execution_class','completed_at_ms','signature_b64url'}
NODE = re.compile(r'^[a-z][a-z0-9._-]{2,63}$')
HEX32 = re.compile(r'^[0-9a-f]{32}$')
HEX64 = re.compile(r'^[0-9a-f]{64}$')
B64URL = re.compile(r'^[A-Za-z0-9_-]+$')

def reject_duplicate(pairs):
    obj = {}
    for key, val in pairs:
        if key in obj:
            raise ValueError('DUPLICATE_JSON_KEY')
        obj[key] = val
    return obj

def decode(s, max_bytes):
    if not isinstance(s, str) or not B64URL.fullmatch(s):
        raise ValueError('INVALID_BASE64URL')
    b = base64.urlsafe_b64decode(s + '='*((-len(s))%4))
    if len(b) > max_bytes or base64.urlsafe_b64encode(b).decode().rstrip('=') != s:
        raise ValueError('NONCANONICAL_BASE64URL')
    return b

def digest(b): return hashlib.sha256(b).hexdigest()

def exact(o, keys):
    if not isinstance(o, dict) or set(o)!=keys: raise ValueError('INVALID_FIELDS')

def verify_request(e, trust_store):
    exact(e,REQ_KEYS)
    if e['protocol'] != PROTOCOL or e['version'] != VERSION: raise ValueError('PROTOCOL_MISMATCH')
    if not all(isinstance(e[k],str) and NODE.fullmatch(e[k]) for k in ('sender','recipient')): raise ValueError('INVALID_NODE')
    if not all(isinstance(e[k],str) and HEX32.fullmatch(e[k]) for k in ('message_id','nonce')): raise ValueError('INVALID_IDENTIFIERS')
    if not all(type(e[k]) is int and 0<=e[k]<=9007199254740991 for k in ('issued_at_ms','expires_at_ms')): raise ValueError('INVALID_TIMESTAMPS')
    if e['operation']!='probe.sha256': raise ValueError('UNSUPPORTED_OPERATION')
    if e['expires_at_ms']<e['issued_at_ms'] or e['expires_at_ms']-e['issued_at_ms']>300000: raise ValueError('INVALID_WINDOW')
    if e['sender'] not in trust_store: raise ValueError('UNTRUSTED_SENDER')
    payload=decode(e['payload_b64url'],65536)
    msg=('\n'.join([PROTOCOL,VERSION,e['sender'],e['recipient'],e['message_id'],e['nonce'],str(e['issued_at_ms']),str(e['expires_at_ms']),e['operation'],digest(payload)])+'\n').encode()
    signature=decode(e['signature_b64url'],64)
    if len(signature)!=64: raise ValueError('INVALID_SIGNATURE_LENGTH')
    key=load_pem_public_key(trust_store[e['sender']].encode())
    try:key.verify(signature,msg)
    except InvalidSignature:raise ValueError('INVALID_SIGNATURE') from None
    return {'signature_valid':True,'request_sha256':digest(msg),'payload_sha256':digest(payload),'evidence_scope':'signature_only'}

def verify_receipt(r,public_pem):
    exact(r,RCPT_KEYS)
    if r['protocol']!=PROTOCOL or r['version']!=VERSION: raise ValueError('PROTOCOL_MISMATCH')
    if not isinstance(r['node_id'],str) or not NODE.fullmatch(r['node_id']): raise ValueError('INVALID_NODE')
    if not all(isinstance(r[k],str) and HEX64.fullmatch(r[k]) for k in ('request_sha256','result_sha256')):raise ValueError('INVALID_DIGEST')
    if r['status']!='completed' or r['execution_class']!='local_integrity_probe':raise ValueError('INVALID_EXECUTION_SCOPE')
    if type(r['completed_at_ms']) is not int:raise ValueError('INVALID_TIMESTAMP')
    msg=('\n'.join([PROTOCOL,VERSION,r['node_id'],r['request_sha256'],r['result_sha256'],r['status'],r['execution_class'],str(r['completed_at_ms'])])+'\n').encode()
    sig=decode(r['signature_b64url'],64)
    if len(sig)!=64:raise ValueError('INVALID_SIGNATURE_LENGTH')
    key=load_pem_public_key(public_pem.encode())
    try:key.verify(sig,msg)
    except InvalidSignature:raise ValueError('INVALID_SIGNATURE') from None
    return {'signature_valid':True,'request_sha256':r['request_sha256'],'result_sha256':r['result_sha256'],'evidence_scope':r['execution_class']}

def main(args):
    if len(args)!=3 or args[0] not in ('request','receipt'):
        raise ValueError('Usage: verify_cross_runtime.py request TRUST.json ENVELOPE.json | receipt NODE_PUBLIC.pem RECEIPT.json')
    kind,trust_path,payload_path=args
    obj=json.loads(Path(payload_path).read_text(),object_pairs_hook=reject_duplicate)
    if kind=='request':
        trust=json.loads(Path(trust_path).read_text(),object_pairs_hook=reject_duplicate)
        result=verify_request(obj,trust)
    else:result=verify_receipt(obj,Path(trust_path).read_text())
    print(json.dumps(result,sort_keys=True))

if __name__=='__main__':
    try:main(sys.argv[1:])
    except Exception as err:print(json.dumps({'verified':False,'error':str(err)}),file=sys.stderr);raise SystemExit(1)