

'''
$GHIDRA_HOME/support/analyzeHeadless /tmp/myghidra/ sample155 -import e2e/target.o -overwrite -postscript e2e/ghidra_extract_bb.py ointerest e2e/target_cfg_summary.json
'''
import tempfile
import os
import subprocess
import json

from lifting import pcode_lifter
from preprocess import preprocessing_pcode
from model.core.config import load_config_from_json
from model.core import GNNModel, batch_to
from model.core.graph_factory_base import pack_batch

GHIDRA_HOME = os.getenv("GHIDRA_HOME")
if GHIDRA_HOME is None:
    raise ValueError("GHIDRA_HOME is not set")


def ghidra_extract_bb(ghidra_path, binary_path, function_name, output_file):
    
    with tempfile.TemporaryDirectory() as tmpdir:
        subprocess.run([
            os.path.join(ghidra_path, "support/analyzeHeadless"),
            tmpdir,  # This is the Ghidra project directory
            os.path.basename(binary_path),  # Project name (can be arbitrary, here use binary file name)
            "-import", binary_path,
            "-overwrite",
            "-postscript", "e2e/ghidra_extract_bb.py", function_name, output_file
        ])


def load_opc_dicts(opc_dict_dir):
    opc_dicts = {}
    for gtype in preprocessing_pcode.GRAPH_TYPES:
        sub_dir = os.path.join(opc_dict_dir, f'pcode_{gtype.lower()}')
        json_path = os.path.join(sub_dir, "opcodes_dict.json")
        if not os.path.isfile(json_path):
            print("[!] Error loading {}".format(json_path))
            return None
        with open(json_path) as f_in:
            opc_dict = json.load(f_in)
            opc_dicts[gtype] = opc_dict
    return opc_dicts


def load_model(workingdir, subdir):
    config = load_config_from_json(workingdir)
    ckpt_file_path = os.path.join(workingdir, subdir, "checkpoint_19.pt")
    gnn_model = GNNModel(config)
    if not gnn_model._inited:
        gnn_model._model_initialize()
        gnn_model._restore_model(ckpt_file_path)
        print(
            f"Tot. Param. {sum(p.numel() for p in gnn_model._model.parameters())}")
    return gnn_model

def main():
    base_dir = "e2e"
    bin_file = 'x64-target.o'
    opc_dict_dir = "inputs/pcode_raw/"
    cfg_summary_file = os.path.join(base_dir, f"{bin_file}_cfg_summary.json")
    bin_file_path = os.path.join(base_dir, bin_file)
    # ghidra_extract_bb(GHIDRA_HOME, bin_file_path, "ointerest", cfg_summary_file)
    # pcode_lifter.do_one_extractor(cfg_summary_file, "ALL", 1, base_dir, bin_fp=bin_file_path)
    opc_dicts = load_opc_dicts(opc_dict_dir)
    acfg_disasm_file = os.path.join(base_dir, f"{bin_file}_acfg_disasm.json")
    idb_path, str_func_dict, pkl_func_dict = preprocessing_pcode.process_one_file((acfg_disasm_file, opc_dicts, True, True))
    print(idb_path)
    print(str_func_dict)
    print(pkl_func_dict)
    graph_type, working_dir, sub_dir = "SOG", "outputs/experiments/hermes_sim/9", "graph-ggnn-batch_pair-pcode_sog"
    # graph_type, working_dir, sub_dir = "ISCG", "outputs/experiments/representations/iscg/9", "graph-ggnn-batch_pair-pcode_iscg"

    gnn_model = load_model(working_dir, sub_dir)
    iscg_graph, iscg_feature = pkl_func_dict[graph_type]['0x100000']['graph'], pkl_func_dict[graph_type]['0x100000']['opc']
    node_features, edge_index, edge_feat, graph_idx, batch_size = pack_batch([iscg_graph], [iscg_feature])

    gnn_model.trace_model(batch_to((node_features, edge_index, edge_feat, graph_idx, batch_size), device="cuda:0"))
    embeddings = gnn_model._embed_one_batch(node_features, edge_index, edge_feat, graph_idx, batch_size)
    print(embeddings)


if __name__ == "__main__":
    main()
