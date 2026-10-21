from pathlib import Path
import json,struct,subprocess,tempfile,hashlib,os
root=Path(__file__).resolve().parent
b=bytearray((root/'add.aot').read_bytes())
sections={}; p=8
while p<len(b):
 p=(p+3)&~3
 t,n=struct.unpack_from('<II',b,p); sections[t]=(p+8,n); p+=8+n
rel,size=sections[5]
count=struct.unpack_from('<I',b,rel)[0]
offsets=rel+4; total_at=offsets+count*4
string_base=total_at+4; total=struct.unpack_from('<I',b,total_at)[0]
group_count_at=(string_base+total+3)&~3
record=group_count_at+12
assert record%8==4, 'fixture must exercise 4-aligned u64'
results=[]
for name,fragment,imports in [('add.aot','fib+0x1b -> fib [target file@0x174]',0),('add_aarch64.aot','R_AARCH64_CALL26(283)',0),('add_riscv64.aot','R_RISCV_CALL_PLT(19)',0),('add_i386.aot','fib+0x69 -> fib',0),('import.aot','bounce+0x1a -> bounce',1)]:
 p=subprocess.run([str(root/'unaot-sanitize'),'--no-color','--imports',str(imports),str(root/name)],capture_output=True,text=True)
 assert p.returncode==0 and fragment in p.stdout and not p.stderr,(name,p.stderr)
 (root/(name+'.txt')).write_text(p.stdout)
 results.append({'fixture':name,'sha256':hashlib.sha256((root/name).read_bytes()).hexdigest(),'passed':True})
p=subprocess.run([str(root/'unaot'),str(root/'add.aot')],capture_output=True,text=True)
assert 'export names unresolved' in p.stdout and 'fib' not in p.stdout
rejected=[]
mutations={
 'symbol_count_overflow':(rel,'I',0xffffffff),
 'string_table_outside_section':(total_at,'I',0xffffffff),
 'symbol_offset_outside_table':(offsets,'I',total),
 'symbol_index_out_of_range':(record+20,'I',count),
 'group_name_index_out_of_range':(group_count_at+4,'I',count),
 'group_count_overflow':(group_count_at,'I',0xffffffff),
 'relocation_count_overflow':(group_count_at+8,'I',0xffffffff),
 'code_offset_out_of_range':(record,'Q',84),
 'literal_size_overflow':(sections[2][0],'I',0xffffffff),
 'unsupported_version':(4,'I',6),
}
with tempfile.TemporaryDirectory(prefix='unaot-negative-') as tmp:
 path=Path(tmp)/'case.aot'
 for name,(at,fmt,value) in mutations.items():
  x=bytearray(b); struct.pack_into('<'+fmt,x,at,value); path.write_bytes(x)
  p=subprocess.run([str(root/'unaot-sanitize'),str(path)],capture_output=True,text=True)
  assert p.returncode==1 and 'Sanitizer' not in p.stderr,(name,p.stderr)
  rejected.append(name)
 x=bytearray(b)
 first=string_base+struct.unpack_from('<I',x,offsets)[0]
 slen=struct.unpack_from('<H',x,first)[0]; x[first+2+slen-1]=ord('X'); path.write_bytes(x)
 p=subprocess.run([str(root/'unaot-sanitize'),str(path)],capture_output=True,text=True)
 assert p.returncode==1 and 'Sanitizer' not in p.stderr
 rejected.append('missing_symbol_NUL')
 for n in range(len(b)):
  path.write_bytes(b[:n])
  p=subprocess.run([str(root/'unaot'),str(path)],capture_output=True)
  assert p.returncode==1,('truncation',n,p.returncode)
code=bytes(b[0x154:0x1a8]); assert code[0x3a:0x3f]==b'\xe8\0\0\0\0'
(root/'text.bin').write_bytes(code)
relocated=bytearray(code); struct.pack_into('<i',relocated,0x3b,0x20-4-0x3b)
(root/'text-relocated.bin').write_bytes(relocated)
report={'fixtures':results,'negative_cases':rejected,'all_prefix_truncations_rejected':len(b),'sanitizers':'AddressSanitizer + UndefinedBehaviorSanitizer; no findings in valid and targeted malformed cases','x86_patch_field_file_offset':'0x18f','x86_call_instruction_file_offset':'0x18e','x86_fib_entry_file_offset':'0x174','relocation_record_alignment':4}
(root/'check-results.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
