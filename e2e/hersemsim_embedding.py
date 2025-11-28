
import tempfile
import os
import subprocess
import json
from typing import List, Tuple

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


def load_model(workingdir, subdir, checkpoint_name='checkpoint_19.pt'):
    config = load_config_from_json(workingdir)
    ckpt_file_path = os.path.join(workingdir, subdir, checkpoint_name)
    gnn_model = GNNModel(config)
    if not gnn_model._inited:
        gnn_model._model_initialize()
        gnn_model._restore_model(ckpt_file_path)
        print(
            f"Tot. Param. {sum(p.numel() for p in gnn_model._model.parameters())}")
    return gnn_model


def test():
    base_dir = "e2e"
    bin_file = 'x64-target.o'
    opc_dict_dir = "inputs/pcode_raw/"
    cfg_summary_file = os.path.join(base_dir, f"{bin_file}_cfg_summary.json")
    bin_file_path = os.path.join(base_dir, bin_file)
    ghidra_extract_bb(GHIDRA_HOME, bin_file_path, "ointerest", cfg_summary_file)
    pcode_lifter.do_one_extractor(cfg_summary_file, "ALL", 1, base_dir, bin_fp=bin_file_path)
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


class HersemSimEmbedding:
    def __init__(self, working_dir, sub_dir, graph_type, opc_dict_dir, device='cuda:0'):
        self.gnn_model = load_model(working_dir, sub_dir)
        self.working_dir = working_dir
        self.sub_dir = sub_dir
        self.graph_type = graph_type
        self.opc_dict_dir = opc_dict_dir
        self.opc_dicts = load_opc_dicts(self.opc_dict_dir)
        self.device = device


    def _extract_features(self, binary_path, func_name, arch='x64'):
        file_name = os.path.basename(binary_path)
        folder_path = os.path.dirname(binary_path)
        # 1. Ensure the file name start from arch
        if not file_name.startswith(arch):
            arch_file_name = arch + '-' + file_name
            arch_binary_path = os.path.join(folder_path, arch_file_name)
            os.system(f"cp {binary_path} {arch_binary_path}")
            file_name = arch_file_name
            binary_path = arch_binary_path
        # 2. Use ghidra to extract the cfg to get the 
        cfg_summary_file = os.path.join(folder_path, file_name + '_cfg_summary.json')
        ghidra_extract_bb(GHIDRA_HOME, binary_path, func_name, cfg_summary_file)

        # 3. Use GSAT to extract the all the graph types
        pcode_lifter.do_one_extractor(cfg_summary_file, "ALL", 1, folder_path, bin_fp=binary_path)
        acfg_disasm_file = os.path.join(folder_path, file_name + '_acfg_disasm.json')

        # 4. Process the disasm file to extract the graph and op code features
        idb_path, str_func_dict, pkl_func_dict = preprocessing_pcode.process_one_file((acfg_disasm_file, self.opc_dicts, True, True))

        # 5. Pack the graph and op code features so that can be fed to GNN model
        start_ae = list(pkl_func_dict[self.graph_type].keys())[0]
        graph_feature = pkl_func_dict[self.graph_type][start_ae]['graph']
        opc_feature = pkl_func_dict[self.graph_type][start_ae]['opc']

        return graph_feature, opc_feature

    def _extract_features_batch(self, binary_path_func_name_list: List[Tuple[str, str]], nproc=8):
        import concurrent.futures

        def _extract_features_wrapper(args):
            # Helper for multiprocessing: unpack the tuple and call method
            self, binary_path, func_name = args
            return self._extract_features(binary_path, func_name)

        graph_feature_list = []
        opc_feature_list = []
        # Prepare the argument tuples
        args_list = [(self, binary_path, func_name) for binary_path, func_name in binary_path_func_name_list]
        with concurrent.futures.ProcessPoolExecutor() as executor:
            results = list(executor.map(_extract_features_wrapper, args_list))
        for graph_feature, opc_feature in results:
            graph_feature_list.append(graph_feature)
            opc_feature_list.append(opc_feature)
        return graph_feature_list, opc_feature_list


    def _embed(self, graph_feature_list: List[dict], opc_feature_list: List[dict]):
        node_features, edge_index, edge_feat, graph_idx, batch_size = pack_batch(graph_feature_list, opc_feature_list)
        batch_to((node_features, edge_index, edge_feat, graph_idx, batch_size), self.device)
        embeddings = self.gnn_model._embed_one_batch(node_features, edge_index, edge_feat, graph_idx, batch_size)
        return embeddings


    def get_binary_embedding(self, binary_path, func_name):
        graph_feature, opc_feature = self._extract_features(binary_path, func_name)
        embeddings = self._embed([graph_feature], [opc_feature])
        return embeddings


    def get_binary_embedding_batch(self, binary_path_func_name_list: List[Tuple[str, str]]):
        graph_feature_list, opc_feature_list = self._extract_features_batch(binary_path_func_name_list)
        embeddings = self._embed(graph_feature_list, opc_feature_list)
        return embeddings
    

if __name__ == "__main__":
    test()
