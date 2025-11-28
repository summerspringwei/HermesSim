`python lifting/dataset_summary.py \
    --cfg_summary /home/xiachunwei/Projects/binary_function_similarity/DBs/Dataset-1/cfg_summary/testing \
    --dataset_info_csv /home/xiachunwei/Projects/binary_function_similarity/DBs/Dataset-1/testing_Dataset-1.csv \
    --cfgs_folder /home/xiachunwei/Projects/binary_function_similarity/DBs/Dataset-1/features/testing/acfg_features_Dataset-1_testing
`
python lifting/pcode_lifter.py \
    --cfg_summary /home/xiachunwei/Projects/binary_function_similarity/DBs//Dataset-1/cfg_summary/testing \
    --output_dir /home/xiachunwei/Projects/binary_function_similarity/DBs//Dataset-1/features/testing/pcode_raw_Dataset-1_testing \
    --graph_type ALL \
    --verbose 1 \
    --nproc 64


java -ea -Xmx16G -XX:+UseCompressedOops -jar bin/gsat-1.0.jar pcode-extractor-v2 -m elf         -f binaries/Dataset-1/nmap/x64-clang-7-O1_ncat -c /home/xiachunwei/Projects/binary_function_similarity/DBs//Dataset-1/cfg_summary/testing/x64-clang-7-O1_ncat_cfg_summary.json -of ALL -v 1        -opt 0 -o /home/xiachunwei/Projects/binary_function_similarity/DBs//Dataset-1/features/testing/pcode_raw_Dataset-1_testing/x64-clang-7-O1_ncat_acfg_disasm.json

python3 preprocess/preprocessing_pcode.py  --freq-mode -f pkl -s Dataset-1_testing -i /home/xiachunwei/Projects/binary_function_similarity/DBs/Dataset-1/features/testing/pcode_raw_Dataset-1_testing -o


python lifting/pcode_lifter.py \
    --cfg_summary ./dbs/Dataset-1/cfg_summary/testing \
    --output_dir ./dbs/Dataset-1/features/testing/xcw_pcode_raw_Dataset-1_testing \
    --graph_type ALL \
    --verbose 1 \
    --nproc 80