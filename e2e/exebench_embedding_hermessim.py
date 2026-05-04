
import os
import sys
import subprocess
from datasets import load_from_disk
from tqdm import tqdm

# Add the e2e directory to the path so we can import hersemsim_embedding
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from hersemsim_embedding import HersemSimEmbedding

def compile_asm_to_binary(record, work_dir, idx, compiler: str = 'gcc'):
    """
    Compiles assembly code in record['asm']['code'][-1] to a binary file named '{record['fname']}.o'
    in the current directory.

    Args:
        record: A dataset record with keys 'asm' (dict with 'code' as list) and 'fname' (output name).
        work_dir: Working directory where compiled binaries will be stored.
        idx: Index of record (used for creating subdirectories).
        compiler: The compiler to use for compilation.
    Returns:
        output_file: The path to the compiled object file, or None if compilation failed.
    """
    
    asm_code = record['asm']['code'][-1]
    fname = record['fname']
    
    # Create subdirectory for this record
    record_dir = os.path.join(work_dir, str(idx))
    if not os.path.exists(record_dir):
        os.makedirs(record_dir)
    
    # Write assembly code to file
    asm_file = os.path.join(record_dir, f"{fname}.s")
    with open(asm_file, "w") as f:
        f.write(asm_code)
    
    # Compile assembly to object file
    output_file = os.path.join(record_dir, f"{fname}.o")
    try:
        # -c: compile only, don't link
        # -m64: ensure 64-bit (x86-64)
        result = subprocess.run(
            [compiler, '-c', '-m64', asm_file, '-o', output_file],
            capture_output=True,
            text=True,
            check=True
        )
        if result.returncode != 0:
            print(f"[!] Failed to compile {asm_file}: {result.stderr}")
            return None
        return output_file
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to compile {asm_file}: {e.stderr}")
        return None
    except Exception as e:
        print(f"[!] Error compiling {asm_file}: {e}")
        return None


def exebench_embedding_hermessim(
    exebench_dataset,
    working_dir="outputs/experiments/hermes_sim/9",
    sub_dir="graph-ggnn-batch_pair-pcode_sog",
    graph_type="SOG",
    opc_dict_dir="inputs/pcode_raw/",
    device='cuda:0',
    work_dir="e2e/exebench_test_outputs"
):
    """
    Test the embedding function on the exebench dataset.
    
    Args:
        num_samples: Number of samples to test (None for all)
        working_dir: Model working directory
        sub_dir: Model subdirectory
        graph_type: Graph type to use (SOG, ISCG, etc.)
        opc_dict_dir: Directory containing opcode dictionaries
        device: Device to use for inference
        work_dir: Working directory for compiled binaries and intermediate files
    """
    
    # Create working directory
    if not os.path.exists(work_dir):
        os.makedirs(work_dir)
    
    # Initialize the embedding model
    print(f"[*] Initializing HersemSimEmbedding model...")
    print(f"    working_dir: {working_dir}")
    print(f"    sub_dir: {sub_dir}")
    print(f"    graph_type: {graph_type}")
    print(f"    opc_dict_dir: {opc_dict_dir}")
    
    try:
        embedding_model = HersemSimEmbedding(
            working_dir=working_dir,
            sub_dir=sub_dir,
            graph_type=graph_type,
            opc_dict_dir=opc_dict_dir,
            device=device
        )
        print("[+] Model initialized successfully")
    except Exception as e:
        print(f"[!] Failed to initialize model: {e}")
        return
    
    # Determine number of samples to process
    dataset_size = len(exebench_dataset)
    if num_samples is None:
        num_samples = dataset_size
    else:
        num_samples = min(num_samples, dataset_size)
    
    print(f"[*] Processing {num_samples} samples from exebench dataset...")
    
    successful = 0
    failed = 0
    binary_func_list = []
    # Process each sample
    for idx in tqdm(range(num_samples), desc="Processing samples"):
        record = exebench_dataset[idx]
        fname = record['fname']
        try:
            # Compile assembly to binary
            binary_path = compile_asm_to_binary(record, work_dir, idx)
            if binary_path is None:
                print(f"[!] Failed to compile sample {idx} ({fname})")
                failed += 1
                continue
            binary_func_list.append((binary_path, None))
        except Exception as e:
            print(f"[!] Error processing sample {idx} ({fname}): {e}")
            failed += 1
    
    # 1. Test in sequtial
    success_count = 0
    failed_count = 0
    # 2. Test in batch
    embeddings = embedding_model.get_binary_embedding_batch(binary_func_list, nproc=32)
    print(embeddings.shape)
    print(f"[+] Success count: {success_count}")
    print(f"[+] Failed count: {failed_count}")
    return embeddings
