"""
Web service for HermesSim embedding extraction.

This service provides REST API endpoints to get embeddings from exebench dataset records
using the HersemSimEmbedding model. It accepts records in the format from exebench_dataset[idx],
which includes assembly code that will be compiled to binary before extracting embeddings.

Usage:
    python hermessim_embedding_service.py
    
    Or with uvicorn:
    uvicorn hermessim_embedding_service:app --host 0.0.0.0 --port 8000
"""

import os
import sys
import subprocess
import tempfile
import uuid
import traceback
from typing import List, Optional, Dict, Any
import logging
import uvicorn
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Add the e2e directory to the path so we can import hersemsim_embedding
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from hersemsim_embedding import HersemSimEmbedding

# Configuration - can be set via environment variables or modified here
WORKING_DIR = os.getenv("HERMESSIM_WORKING_DIR", "outputs/experiments/hermes_sim/9")
SUB_DIR = os.getenv("HERMESSIM_SUB_DIR", "graph-ggnn-batch_pair-pcode_sog")
GRAPH_TYPE = os.getenv("HERMESSIM_GRAPH_TYPE", "SOG")
OPC_DICT_DIR = os.getenv("HERMESSIM_OPC_DICT_DIR", "inputs/pcode_raw/")
DEVICE = os.getenv("HERMESSIM_DEVICE", "cuda:0")
NPROC = int(os.getenv("HERMESSIM_NPROC", "64"))
WORK_DIR = os.getenv("HERMESSIM_WORK_DIR", None)  # If None, uses temp directory
COMPILER = os.getenv("HERMESSIM_COMPILER", "clang")

# Global embedding model instance
embedding_model: Optional[HersemSimEmbedding] = None
# Global work directory for compiled binaries
work_dir: Optional[str] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize the embedding model and work directory on startup."""
    global embedding_model, work_dir
    
    # Set up work directory
    if WORK_DIR is None:
        work_dir = tempfile.mkdtemp(prefix="hermessim_embedding_")
        logger.info(f"Using temporary work directory: {work_dir}")
    else:
        work_dir = WORK_DIR
        if not os.path.exists(work_dir):
            os.makedirs(work_dir)
        logger.info(f"Using work directory: {work_dir}")
    
    logger.info("Initializing HersemSimEmbedding model...")
    logger.info(f"    working_dir: {WORKING_DIR}")
    logger.info(f"    sub_dir: {SUB_DIR}")
    logger.info(f"    graph_type: {GRAPH_TYPE}")
    logger.info(f"    opc_dict_dir: {OPC_DICT_DIR}")
    logger.info(f"    device: {DEVICE}")
    logger.info(f"    nproc: {NPROC}")
    logger.info(f"    compiler: {COMPILER}")
    
    try:
        embedding_model = HersemSimEmbedding(
            working_dir=WORKING_DIR,
            sub_dir=SUB_DIR,
            graph_type=GRAPH_TYPE,
            opc_dict_dir=OPC_DICT_DIR,
            device=DEVICE
        )
        logger.info("Model initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize model: {e}")
        logger.error(traceback.format_exc())
        raise
    
    yield
    # Shutdown logic
    logger.info("Shutting down HermesSim Embedding Service...")


# Initialize FastAPI app
app = FastAPI(
    title="HermesSim Embedding Service",
    description="REST API for extracting embeddings from binary files using HermesSim",
    version="1.0.0",
    lifespan=lifespan
)


def compile_asm_to_binary(asm_code: str, work_dir: str, fname: Optional[str] = None, idx: Optional[str] = None, compiler: str = 'gcc') -> Optional[str]:
    """
    Compiles assembly code to a binary file.
    
    Args:
        asm_code: Assembly code to compile.
        work_dir: Working directory where compiled binaries will be stored.
        fname: Function name to use for the binary file. If None, uses UUID.
        work_dir: Working directory where compiled binaries will be stored.
        idx: Optional index/identifier for creating subdirectories. If None, uses UUID.
        compiler: The compiler to use for compilation.
    Returns:
        output_file: The path to the compiled object file, or None if compilation failed.
    """
    
    
    fname = str(uuid.uuid4().hex) if fname is None else fname
    
    # Create subdirectory for this record
    if idx is None:
        idx = str(uuid.uuid4())
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
            raise RuntimeError(f"Compilation failed: {result.stderr}")
        return output_file
    except subprocess.CalledProcessError as e:
        # raise RuntimeError(f"Failed to compile {asm_file}: {e.stderr}")
        logger.error(f"Failed to compile {asm_file}: {e.stderr}")
        return None
    except Exception as e:
        # raise RuntimeError(f"Error compiling {asm_file}: {str(e)}")
        logger.error(f"Error compiling {asm_file}: {str(e)}")
        return None


# Request/Response models
class ExebenchRecord(BaseModel):
    """Model for exebench dataset record format."""
    asm: Dict[str, Any]  # Should have 'code' field (list or string)
    fname: str
    # Allow extra fields that might be in the record
    class Config:
        extra = "allow"


class RecordResponse(BaseModel):
    """Response model for a single embedding."""
    embeddings: List[List[float]]
    shape: List[int]
    binary_path: Optional[str] = None  # Path to compiled binary


class BatchRecordRequest(BaseModel):
    """Request model for batch records."""
    records: List[ExebenchRecord]


class BatchRecordResponse(BaseModel):
    """Response model for batch embeddings."""
    embeddings: List[List[float]]
    success_indices: List[int]
    count: int
    binary_paths: Optional[List[str]] = None  # Paths to compiled binaries


@app.get("/")
async def root():
    """Root endpoint with service information."""
    return {
        "service": "HermesSim Embedding Service",
        "version": "1.0.0",
        "status": "running",
        "endpoints": {
            "/embed": "POST - Get embedding for a single exebench record",
            "/embed/batch": "POST - Get embeddings for a list of exebench records",
            "/health": "GET - Health check"
        },
        "record_format": {
            "asm": {"code": "list or string containing assembly code"},
            "fname": "function name"
        }
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    if embedding_model is None:
        raise HTTPException(status_code=503, detail="Model not initialized")
    return {"status": "healthy", "model_loaded": True}


@app.post("/embed", response_model=RecordResponse)
async def get_embedding(asm_code: str = Body(...)):
    """
    Get embedding for a single exebench dataset record.
    
    The record should be in the format from exebench_dataset[idx], containing:
    - asm: dict with 'code' field (list or string) containing assembly code
    - fname: function name
    
    The service will compile the assembly code to binary and then extract the embedding.
    
    Args:
        record: Exebench record containing assembly code and function name
        
    Returns:
        RecordResponse with embedding, shape, and binary_path
    """
    if embedding_model is None:
        raise HTTPException(status_code=503, detail="Model not initialized")
    
    if work_dir is None:
        raise HTTPException(status_code=503, detail="Work directory not initialized")
    
    try:
        # Compile assembly to binary
        binary_path = compile_asm_to_binary(
            asm_code=asm_code,
            fname=None,
            work_dir=work_dir,
            idx=None,  # Will use UUID
            compiler=COMPILER
        )
        logger.info(f"Binary path: {binary_path}")
        if binary_path is None:
            raise HTTPException(
                status_code=500,
                detail="Failed to compile assembly to binary"
            )
        
        # Get embedding from compiled binary
        embeddings = embedding_model.get_binary_embedding(
            binary_path=binary_path,
            func_name=None  # Function name not needed for single function binaries
        )
        
        # Convert numpy array to list for JSON serialization
        embedding_list = embeddings.tolist()
        
        return RecordResponse(
            embedding=embedding_list,
            shape=list(embeddings.shape),
            binary_path=binary_path
        )
    except ValueError as e:
        logger.error(f"ValueError in /embed: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(
            status_code=400,
            detail=f"Invalid record format: {str(e)}"
        )
    except RuntimeError as e:
        logger.error(f"RuntimeError in /embed: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(
            status_code=500,
            detail=f"Compilation error: {str(e)}"
        )
    except Exception as e:
        logger.error(f"Unexpected error in /embed: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(
            status_code=500,
            detail=f"Error processing embedding: {str(e)}"
        )


@app.post("/embed/batch", response_model=BatchRecordResponse)
async def get_embeddings_batch(asm_code_list: List[str] = Body(...)):
    """
    Get embeddings for a list of exebench dataset records.
    
    Each record should be in the format from exebench_dataset[idx], containing:
    - asm: dict with 'code' field (list or string) containing assembly code
    - fname: function name
    
    The service will compile all assembly codes to binaries and then extract embeddings in batch.
    
    Args:
        batch_request: BatchRecordRequest containing a list of exebench records
        
    Returns:
        BatchRecordResponse with embeddings, shape, count, and binary_paths
    """
    if embedding_model is None:
        raise HTTPException(status_code=503, detail="Model not initialized")
    
    if work_dir is None:
        raise HTTPException(status_code=503, detail="Work directory not initialized")
    
    try:
        logger.info(f"Processing batch request with {len(asm_code_list)} records")
        
        # Compile all assembly codes to binaries
        binary_func_list = []
        binary_paths = []
        compiled_indices = []
        
        for idx, asm_code in enumerate(asm_code_list):
            try:
                logger.debug(f"Compiling assembly code {idx}/{len(asm_code_list)}")
                # Compile assembly to binary
                binary_path = compile_asm_to_binary(
                    asm_code=asm_code,
                    fname=None,
                    work_dir=work_dir,
                    idx=None,  # Will use UUID
                    compiler=COMPILER
                )
                
                if binary_path is None:
                    raise RuntimeError(f"Failed to compile assembly {idx}")
                
                binary_func_list.append((binary_path, None))  # func_name not needed
                binary_paths.append(binary_path)
                compiled_indices.append(idx)
                logger.debug(f"Successfully compiled assembly {idx} to {binary_path}")
            except Exception as e:
                # Log error with full traceback
                logger.error(f"Error compiling assembly {idx}: {str(e)}")
                logger.error(traceback.format_exc())
                # You might want to handle this differently - either skip or fail all
                raise HTTPException(
                    status_code=500,
                    detail=f"Error compiling assembly {idx}: {str(e)}"
                )
        
        if not binary_func_list:
            logger.error("No records were successfully compiled")
            raise HTTPException(
                status_code=500,
                detail="No records were successfully compiled"
            )
        
        logger.info(f"Successfully compiled {len(binary_func_list)} binaries, starting batch embedding extraction...")
        
        # Get embeddings in batch
        try:
            embeddings, success_indices, failures = embedding_model.get_binary_embedding_batch(
                binary_path_func_name_list=binary_func_list,
                nproc=NPROC
            )
            logger.info(f"Successfully extracted embeddings, success/total: {len(success_indices)}/ {len(binary_func_list)}")
        except Exception as e:
            logger.error(f"Error during batch embedding extraction: {str(e)}")
            logger.error(traceback.format_exc())
            raise HTTPException(
                status_code=500,
                detail=f"Error during batch embedding extraction: {str(e)}"
            )
        
        logger.info(f"Successfully processed batch request, returning {len(binary_func_list)} embeddings")
        return BatchRecordResponse(
            embeddings=embeddings,
            success_indices=success_indices,
            count=len(binary_func_list),
            binary_paths=binary_paths
        )
    except HTTPException:
        raise
    except ValueError as e:
        logger.error(f"ValueError in /embed/batch: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(
            status_code=400,
            detail=f"Invalid record format: {str(e)}"
        )
    except Exception as e:
        logger.error(f"Unexpected error in /embed/batch: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(
            status_code=500,
            detail=f"Error processing batch embeddings: {str(e)}"
        )


if __name__ == "__main__":
    # Run the service
    uvicorn.run(
        "hermessim_embedding_service:app",
        host="0.0.0.0",
        port=8125,
        reload=False
    )

