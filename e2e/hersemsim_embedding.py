

import os
import json
import tempfile
import subprocess
import concurrent.futures
import numpy as np
import torch
from typing import List, Tuple

from lifting import pcode_lifter
from preprocess import preprocessing_pcode
from model.core.config import load_config_from_json
from model.core import GNNModel, batch_to
from model.core.graph_factory_base import pack_batch

GHIDRA_HOME = os.getenv("GHIDRA_HOME")
if GHIDRA_HOME is None:
    raise ValueError("GHIDRA_HOME is not set")


def ghidra_extract_binary_cfg_summary_json(ghidra_path: str, binary_path: str, output_file: str, function_name: str = None) -> int:
    """
    Extract the CFG of the binary using Ghidra.
    Args:
        ghidra_path: The path to the Ghidra executable.
        binary_path: The path to the binary file.
        output_file: The path to the output file.
        function_name: The name of the function to extract the CFG of. If None, extract the CFG of all functions.
    Returns:
        returncode: The return code of the subprocess.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        if function_name is None:
            args = [
                os.path.join(ghidra_path, "support/analyzeHeadless"),
                tmpdir,  # This is the Ghidra project directory
                os.path.basename(binary_path),  # Project name (can be arbitrary, here use binary file name)
                "-import", binary_path,
                "-overwrite",
                "-postscript", "e2e/ghidra_extract_bb.py", output_file
            ]
        else:
            args = [
                os.path.join(ghidra_path, "support/analyzeHeadless"),
                tmpdir,  # This is the Ghidra project directory
                os.path.basename(binary_path),  # Project name (can be arbitrary, here use binary file name)
                "-import", binary_path,
                "-overwrite",
                "-postscript", "e2e/ghidra_extract_bb.py", output_file, function_name
            ]
        ret = subprocess.run(args)
        return ret.returncode


def load_opc_dicts(opc_dict_dir: str) -> dict[str, dict]:
    """
    Load the opcode dictionaries from the given directory.
    Args:
        opc_dict_dir: The directory containing the opcode dictionaries.
    Returns:
        opc_dicts: A dictionary of opcode dictionaries.
            The keys are the graph types, and the values are the opcode dictionaries.
    """
    opc_dicts = {}
    for gtype in preprocessing_pcode.GRAPH_TYPES:
        sub_dir = os.path.join(opc_dict_dir, f'pcode_{gtype.lower()}')
        json_path = os.path.join(sub_dir, "opcodes_dict.json")
        if not os.path.isfile(json_path):
            raise FileNotFoundError(f"[!] Error loading {json_path}")
        with open(json_path) as f_in:
            opc_dict = json.load(f_in)
            opc_dicts[gtype] = opc_dict
    return opc_dicts


def load_hersem_sim_model(workingdir: str, subdir: str, checkpoint_name: str = 'checkpoint_19.pt') -> GNNModel:
    """
    Load the HermesSim model from the given working directory and subdirectory.
    Args:
        workingdir: The working directory of the model.
        subdir: The subdirectory of the model.
        checkpoint_name: The name of the checkpoint file.
    Returns:
        gnn_model: The HermesSim model.
    """
    config = load_config_from_json(workingdir)
    ckpt_file_path = os.path.join(workingdir, subdir, checkpoint_name)
    gnn_model = GNNModel(config)
    if not gnn_model._inited:
        gnn_model._model_initialize()   
        gnn_model._restore_model(ckpt_file_path)
        print(f"Tot. Param. {sum(p.numel() for p in gnn_model._model.parameters())}")
    return gnn_model


def _extract_features_worker(args):
    """
    Worker function for multiprocessing feature extraction.
    This is a module-level function that can be pickled.
    Args:
        args: Tuple of (binary_path, func_name, opc_dicts, graph_type)
    Returns:
        graph_feature, opc_feature: The extracted features
    """
    binary_path, func_name, opc_dicts, graph_type = args
    file_name = os.path.basename(binary_path)
    folder_path = os.path.dirname(binary_path)
    arch = 'x64'
    
    # 1. Ensure the file name start from arch
    if not file_name.startswith(arch):
        arch_file_name = arch + '-' + file_name
        arch_binary_path = os.path.join(folder_path, arch_file_name)
        os.system(f"cp {binary_path} {arch_binary_path}")
        file_name = arch_file_name
        binary_path = arch_binary_path
    
    # 2. Use ghidra to extract the cfg to get the 
    cfg_summary_file = os.path.join(folder_path, file_name + '_cfg_summary.json')
    retcode = ghidra_extract_binary_cfg_summary_json(GHIDRA_HOME, binary_path, cfg_summary_file, func_name)
    if retcode != 0:
        raise RuntimeError(f"Failed to extract the cfg summary of the binary {binary_path}")

    # 3. Use GSAT to extract the all the graph types
    pcode_lifter.do_one_extractor(cfg_summary_file, "ALL", 1, folder_path, bin_fp=binary_path)
    acfg_disasm_file = os.path.join(folder_path, file_name + '_acfg_disasm.json')

    # 4. Process the disasm file to extract the graph and op code features
    idb_path, str_func_dict, pkl_func_dict = preprocessing_pcode.process_one_file((acfg_disasm_file, opc_dicts, True, True))

    # 5. Pack the graph and op code features so that can be fed to GNN model
    start_ae = list(pkl_func_dict[graph_type].keys())[0]
    graph_feature = pkl_func_dict[graph_type][start_ae]['graph']
    opc_feature = pkl_func_dict[graph_type][start_ae]['opc']

    return graph_feature, opc_feature


def test():
    base_dir = "e2e"
    bin_file = 'x64-target.o'
    opc_dict_dir = "inputs/pcode_raw/"
    cfg_summary_file = os.path.join(base_dir, f"{bin_file}_cfg_summary.json")
    bin_file_path = os.path.join(base_dir, bin_file)
    ghidra_extract_binary_cfg_summary_json(GHIDRA_HOME, bin_file_path, cfg_summary_file, function_name="ointerest")
    pcode_lifter.do_one_extractor(cfg_summary_file, "ALL", 1, base_dir, bin_fp=bin_file_path)
    opc_dicts = load_opc_dicts(opc_dict_dir)
    acfg_disasm_file = os.path.join(base_dir, f"{bin_file}_acfg_disasm.json")
    idb_path, str_func_dict, pkl_func_dict = preprocessing_pcode.process_one_file((acfg_disasm_file, opc_dicts, True, True))
    print(idb_path)
    print(str_func_dict)
    print(pkl_func_dict)
    graph_type, working_dir, sub_dir = "SOG", "outputs/experiments/hermes_sim/9", "graph-ggnn-batch_pair-pcode_sog"
    # graph_type, working_dir, sub_dir = "ISCG", "outputs/experiments/representations/iscg/9", "graph-ggnn-batch_pair-pcode_iscg"

    gnn_model = load_hersem_sim_model(working_dir, sub_dir)
    iscg_graph, iscg_feature = pkl_func_dict[graph_type]['0x100000']['graph'], pkl_func_dict[graph_type]['0x100000']['opc']
    node_features, edge_index, edge_feat, graph_idx, batch_size = pack_batch([iscg_graph], [iscg_feature])

    gnn_model.trace_model(batch_to((node_features, edge_index, edge_feat, graph_idx, batch_size), device="cuda:0"))
    embeddings = gnn_model._embed_one_batch(node_features, edge_index, edge_feat, graph_idx, batch_size)
    print(embeddings)


class HersemSimEmbedding:
    
    def __init__(self, working_dir: str, sub_dir: str, graph_type: str, opc_dict_dir: str, device: str = 'cuda:0'):
        """
        Extract the features of the binary using HermesSim model.
        Args:
            working_dir: The working directory of the model.
            sub_dir: The subdirectory of the model.
            graph_type: The graph type to use.
            opc_dict_dir: The directory containing the opcode dictionaries.
            device: The device to use for inference.
        Returns:
            None
        """
        self.gnn_model = load_hersem_sim_model(working_dir, sub_dir)
        self.working_dir = working_dir
        self.sub_dir = sub_dir
        self.graph_type = graph_type
        self.opc_dict_dir = opc_dict_dir
        self.opc_dicts = load_opc_dicts(self.opc_dict_dir)
        self.device = device


    def _extract_features(self, binary_path: str, func_name: str = None, arch: str = 'x64') -> Tuple[dict, dict]:
        """
        Extract the features of the binary using HermesSim model.
        Args:
            binary_path: The path to the binary file.
            func_name: The name of the function to extract the features of. If None, extract the features of all functions.
            arch: The architecture of the binary.
        Returns:
            graph_feature: The graph feature of the binary.
            opc_feature: The op code feature of the binary.
        """
        return _extract_features_worker((binary_path, func_name, self.opc_dicts, self.graph_type))

    def _extract_features_batch(self, binary_path_func_name_list: List[Tuple[str, str]], nproc: int = 8):
        """
        Extract the features of the binary using HermesSim model.
        Args:
            binary_path_func_name_list: The list of binary paths and function names.
            nproc: The number of processes to use for extraction.
        Returns:
            graph_feature_list: The list of graph features.
            opc_feature_list: The list of op code features.
        """
        graph_feature_list = []
        opc_feature_list = []
        # Prepare the argument tuples: (binary_path, func_name, opc_dicts, graph_type)
        args_list = [(binary_path, func_name, self.opc_dicts, self.graph_type) 
                     for binary_path, func_name in binary_path_func_name_list]
        with concurrent.futures.ProcessPoolExecutor(max_workers=nproc) as executor:
            results = list(executor.map(_extract_features_worker, args_list))
        for graph_feature, opc_feature in results:
            graph_feature_list.append(graph_feature)
            opc_feature_list.append(opc_feature)
        return graph_feature_list, opc_feature_list


    def _embed(self, graph_feature_list: List[dict], opc_feature_list: List[dict]) -> torch.Tensor:
        """
        Embed the graph and op code features using HermesSim model.
        Args:
            graph_feature_list: The list of graph features.
            opc_feature_list: The list of op code features.
        Returns:
            embeddings: The embeddings of the graph and op code features.
        """
        node_features, edge_index, edge_feat, graph_idx, batch_size = pack_batch(graph_feature_list, opc_feature_list)
        batch_to((node_features, edge_index, edge_feat, graph_idx, batch_size), self.device)
        embeddings = self.gnn_model._embed_one_batch(node_features, edge_index, edge_feat, graph_idx, batch_size)
        return embeddings


    def get_binary_embedding(self, binary_path: str, func_name: str) -> np.ndarray:
        """
        Get the embedding of the binary using HermesSim model.
        Args:
            binary_path: The path to the binary file.
            func_name: The name of the function to extract the features of.
        Returns:
            embeddings: The embeddings of the binary.
        """

        graph_feature, opc_feature = self._extract_features(binary_path, func_name)
        embeddings = self._embed([graph_feature], [opc_feature])
        np_embeddings = embeddings.cpu().numpy()
        return np_embeddings


    def get_binary_embedding_batch(self, binary_path_func_name_list: List[Tuple[str, str]], nproc: int = 8) -> np.ndarray:
        """
        Get the embeddings of the binary using HermesSim model.
        Args:
            binary_path_func_name_list: The list of binary paths and function names.
        Returns:
            embeddings: The embeddings of the binary.
        """
        graph_feature_list, opc_feature_list = self._extract_features_batch(binary_path_func_name_list, nproc=nproc)
        embeddings = self._embed(graph_feature_list, opc_feature_list)
        return embeddings
    

if __name__ == "__main__":
    test()
