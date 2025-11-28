

```bash
$GHIDRA_HOME/support/analyzeHeadless /tmp/myghidra/ sample155 -import e2e/x64-target.o -overwrite -postscript e2e/ghidra_extract_bb.py  e2e/x64-target_cfg_summary.json ointerest
```

```bash
$GHIDRA_HOME/support/analyzeHeadless /tmp/myghidra/ sample155 -import e2e/example.o -overwrite -postscript e2e/ghidra_extract_bb.py e2e/example_cfg_summary.json
```
$GHIDRA_HOME/support/analyzeHeadless /tmp/myghidra/ sample155 -import /home/xiachunwei/Projects/HermesSim/e2e/exebench_test_outputs/38/x64-_ZNSt10_Head_baseILj0EP3CatLb0EEC2Ev.o -overwrite -postscript e2e/ghidra_extract_bb.py  /home/xiachunwei/Projects/HermesSim/e2e/exebench_test_outputs/38/x64-_ZNSt10_Head_baseILj0EP3CatLb0EEC2Ev.o_cfg_summary.json



```bash
java -ea -Xmx16G -XX:+UseCompressedOops -jar bin/gsat-1.0.jar pcode-extractor-v2 -m elf         -f e2e/target.o -c e2e/target_cfg_summary.json -of ALL -v 1        -opt 0 -o e2e/target_acfg_features_disasm.json
```

```bash
java -ea -Xmx16G -XX:+UseCompressedOops -jar bin/gsat-1.0.jar pcode-extractor-v2 -m elf         -f /home/xiachunwei/Projects/binary_function_similarity/Binaries//Dataset-1/z3/mips64-clang-9-O3_z3 -c ./dbs/Dataset-1/cfg_summary/testing/mips64-clang-9-O3_z3_cfg_summary.json -of ALL -v 1        -opt 0 -o ./dbs/Dataset-1/features/testing/xcw_pcode_raw_Dataset-1_testing/mips64-clang-9-O3_z3_acfg_disasm.json
```
