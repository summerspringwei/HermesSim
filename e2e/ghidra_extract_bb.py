# Ghidra Headless Script to Dump Basic Blocks and CFG as JSON
#
# This script is designed to be run from the command line
# using analyzeHeadless. It takes one or two arguments:
# 1. (required) output JSON file path
# 2. (optional) the name or address of the function to analyze
#    If not provided, all functions will be dumped

import sys
import json
import base64
import time
import re

from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor


# --- Helper Functions ---
def is_function_defined(function):
    """Check if a function is defined in the binary (not external/imported)."""
    # External functions are imported functions without actual code in the binary
    if function.isExternal():
        return False
    # Additional check: ensure the function has a body
    try:
        body = function.getBody()
        if body is None or body.isEmpty():
            return False
    except Exception:
        return False
    return True

def normalize_operand(operand_str):
    """Normalize an operand by replacing hex values and specific patterns."""
    # Replace hex immediate values with generic placeholder
    operand_str = re.sub(r'0x[0-9a-fA-F]+', 'himm', operand_str)
    operand_str = re.sub(r'#0x[0-9a-fA-F]+', 'himm', operand_str)
    operand_str = re.sub(r'#-?0x[0-9a-fA-F]+', 'himm', operand_str)
    # Replace decimal immediate values
    operand_str = re.sub(r'#-?\d+', 'himm', operand_str)
    # Normalize spaces
    operand_str = operand_str.replace(' ', '_')
    operand_str = operand_str.replace(',_', ',')
    return operand_str

def normalize_instruction(mnemonic, operands_str):
    """Create normalized instruction representation."""
    norm_operands = normalize_operand(operands_str)
    if norm_operands:
        return "{}_{}".format(mnemonic.lower(), norm_operands)
    else:
        return mnemonic.lower()

def process_function(function, bb_model, listing, monitor):
    """Process a single function and return its CFG data."""
    print("=" * 40)
    print("Analyzing Function: {} at {}".format(function.getName(), function.getEntryPoint()))
    print("=" * 40)
    
    try:
        # Get all CodeBlocks for the function's body
        block_iterator = bb_model.getCodeBlocksContaining(function.getBody(), monitor)
        
        all_blocks = []
        while block_iterator.hasNext():
            all_blocks.append(block_iterator.next())
        
        # Initialize data structure
        nodes = []
        edges = []
        basic_blocks = {}
        
        # 4. --- Process Basic Blocks (Nodes) ---
        print("\n## Processing Basic Blocks ##")
        
        for block in all_blocks:
            start_addr = block.getFirstStartAddress()
            end_addr = block.getMaxAddress()
            block_offset = int(start_addr.getOffset())
            
            print("[+] Block: {} (0x{:x})".format(start_addr, block_offset))
            
            # Collect instruction data
            bb_mnems = []
            bb_norm = []
            bb_disasm = []
            bb_heads = []
            bb_bytes = bytearray()
            
            # Iterate through all instructions in this basic block
            instruction = listing.getInstructionAt(start_addr)
            current_addr = start_addr
            
            while instruction is not None and current_addr <= end_addr:
                # Get instruction address
                instr_offset = int(instruction.getAddress().getOffset())
                bb_heads.append(instr_offset)
                
                # Get the mnemonic
                mnemonic = instruction.getMnemonicString()
                bb_mnems.append(mnemonic.lower())
                
                # Build full operand string
                full_operands = []
                for i in range(instruction.getNumOperands()):
                    full_operands.append(instruction.getDefaultOperandRepresentation(i))
                operands_str = ", ".join(full_operands) if full_operands else ""
                
                # Add to disassembly list
                if operands_str:
                    bb_disasm.append("{} {}".format(mnemonic.lower(), operands_str))
                else:
                    bb_disasm.append(mnemonic.lower())
                
                # Add normalized form
                bb_norm.append(normalize_instruction(mnemonic, operands_str))
                
                # Get raw bytes
                try:
                    instr_bytes = instruction.getBytes()
                    for b in instr_bytes:
                        bb_bytes.append(b & 0xFF)
                except Exception as e:
                    print("  Warning: Could not get bytes for instruction at {}: {}".format(current_addr, e))
                
                # Move to the next instruction
                instruction = instruction.getNext()
                if instruction is not None:
                    current_addr = instruction.getAddress()
                else:
                    break
                    
                # Stop if we've moved beyond this block
                if current_addr > end_addr:
                    break
            
            # Encode bytes to base64
            b64_bytes = base64.b64encode(bytes(bb_bytes)).decode('ascii')
            
            # Calculate block length
            bb_len = len(bb_bytes)
            
            # Store block data
            basic_blocks[str(block_offset)] = {
                "bb_len": bb_len,
                "bb_mnems": bb_mnems,
                "bb_norm": bb_norm,
                "bb_disasm": bb_disasm,
                "b64_bytes": b64_bytes,
                "bb_heads": bb_heads
            }
            
            nodes.append(["0x{:x}".format(block_offset), bb_len])
        
        # 5. --- Process Jump Relationships (Edges) ---
        print("\n## Processing Edges ##")
        for block in all_blocks:
            block_start = block.getFirstStartAddress()
            block_offset = int(block_start.getOffset())
            
            # Get an iterator for all outgoing edges (destinations)
            dest_iter = block.getDestinations(monitor)
            
            if not dest_iter.hasNext():
                print("{} --> [NONE] (Likely a return block)".format(block_start))
                continue
            
            while dest_iter.hasNext():
                dest_ref = dest_iter.next()
                dest_addr = dest_ref.getDestinationAddress()
                dest_offset = int(dest_addr.getOffset())
                
                # Add edge
                edges.append([block_offset, dest_offset])
                print("{} --> {}".format(block_start, dest_addr))
        
        # Return function data
        return {
            "start_ea": '0x{:x}'.format(function.getEntryPoint().getOffset()),
            "func_name": function.getName(),
            "nodes": nodes,
            "edges": edges
        }
        
    except Exception as e:
        print("Error processing function {}: {}".format(function.getName(), e))
        import traceback
        traceback.print_exc()
        return None

# --- 1. Setup ---
# Get the program (this is set by the headless analyzer)
program = currentProgram
if program is None:
    print("Error: 'currentProgram' is not available. Run this via analyzeHeadless.")
    sys.exit(1)

# Get a headless monitor
monitor = ConsoleTaskMonitor()

# --- 2. Get Script Arguments ---
output_file = None
function_name = None
functions_to_process = []

try:
    # getScriptArgs() retrieves cmd-line args passed *after* the script name
    script_args = getScriptArgs()
    if len(script_args) == 0:
        print("Error: Missing required argument.")
        print("Usage: ... -postScript ghidra_extract_bb.py <output_json> [function_name_or_address]")
        sys.exit(1)
    
    # First argument is required: output file
    output_file = script_args[0]
    print("Output file: {}".format(output_file))
    
    # Second argument is optional: function name/address
    if len(script_args) > 1:
        function_name = script_args[1]
        print("Function target: {}".format(function_name))

    # Get the FunctionManager
    func_manager = program.getFunctionManager()
    
    # Determine which functions to process
    if function_name is None:
        # Process all functions
        print("No function specified. Processing all functions...")
        funcs_iter = func_manager.getFunctions(True)
        skipped_external = 0
        for f in funcs_iter:
            if is_function_defined(f):
                functions_to_process.append(f)
            else:
                skipped_external += 1
        print("Found {} functions to process (skipped {} external/imported functions).".format(len(functions_to_process), skipped_external))
    else:
        function = None
        # Process only the specified function
        print("Searching for function by name: '{}'...".format(function_name))
        # getFunctions(True) means iterate forward
        funcs_by_name = func_manager.getFunctions(True)
        for f in funcs_by_name:
            if f.getName() == function_name:
                function = f
                break
        
        if function is None:
            raise ValueError("Function {} not found in the binary {}".format(function_name, program.getExecutablePath()))
        
        # Check if the function is actually defined in the binary
        if not is_function_defined(function):
            raise ValueError("Function {} is external/imported and not defined in the binary {}".format(function_name, program.getExecutablePath()))

        functions_to_process.append(function)
        print("Found function: {} at {}".format(function.getName(), function.getEntryPoint()))

except Exception as e:
    print("Error processing arguments: {}".format(e))
    import traceback
    traceback.print_exc()
    sys.exit(1)

# --- 3. Initialize Analysis Components ---
# Get the Basic Block Model
bb_model = BasicBlockModel(program)
listing = program.getListing()

# Get program file path
program_path = program.getExecutablePath()

# Start timing
start_time = time.time()

# --- 4. Process All Functions ---
print("\n" + "=" * 60)
print("Starting analysis of {} function(s)...".format(len(functions_to_process)))
print("=" * 60)

all_function_data = []

try:
    for idx, function in enumerate(functions_to_process, 1):
        print("\n[{}/{}]".format(idx, len(functions_to_process)))
        func_data = process_function(function, bb_model, listing, monitor)
        # Note, we only append the function data if it has nodes, 
        # because some functions are external/imported and not defined in the binary
        if func_data is not None and len(func_data['nodes']) > 0:
            all_function_data.append(func_data)
    
    # Calculate elapsed time
    elapsed_time = time.time() - start_time
    print("\n" + "=" * 60)
    print("Analysis complete. Processed {} function(s) in {:.2f} seconds.".format(len(all_function_data), elapsed_time))
    print("=" * 60)
    
    # --- 5. Build final JSON structure ---
    result = {
        program_path: all_function_data
    }
    
    # --- 6. Output JSON ---
    json_output = json.dumps(result, indent=4)
    
    print("\n## Writing to file: {} ##".format(output_file))
    with open(output_file, 'w') as f:
        f.write(json_output)
    print("JSON output written successfully!")
    print("Total functions written: {}".format(len(all_function_data)))
    
except Exception as e:
    print("Error during analysis: {}".format(e))
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\nAnalysis complete.")