"""
Example client script for HermesSim Embedding Service.

This script demonstrates how to use the web service to get embeddings from assembly code strings.
"""

import requests
import json
from typing import List, Dict, Optional


# SERVICE_URL = "http://localhost:8123"
SERVICE_URL = "http://localhost:8001"


def get_embedding(asm_code: str) -> Dict:
    """
    Get embedding for a single assembly code string.
    
    Args:
        asm_code: Assembly code as a string
        
    Returns:
        Dictionary containing embedding, shape, and binary_path
    """
    url = f"{SERVICE_URL}/embed"
    
    # For FastAPI with Body() parameter, send the string directly using json parameter
    # This will JSON-encode the string and set Content-Type automatically
    response = requests.post(url, json=asm_code)
    response.raise_for_status()
    return response.json()


def get_embeddings_batch(asm_code_list: List[str]) -> Dict:
    """
    Get embeddings for a batch of assembly code strings.
    
    Args:
        asm_code_list: List of assembly code strings
        
    Returns:
        Dictionary containing embeddings, shape, count, and binary_paths
    """
    url = f"{SERVICE_URL}/embed/batch"
    
    # For FastAPI with Body() parameter, send the list directly using json parameter
    # This will JSON-encode the list and set Content-Type automatically
    response = requests.post(url, json=asm_code_list)
    response.raise_for_status()
    return response.json()


def check_health() -> Dict:
    """Check if the service is healthy."""
    url = f"{SERVICE_URL}/health"
    response = requests.get(url)
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    # Example usage
    
    # 1. Check service health
    print("Checking service health...")
    try:
        health = check_health()
        print(f"Service status: {health}")
    except Exception as e:
        print(f"Service is not available: {e}")
        exit(1)
    
    # 2. Example: Get embedding for a single assembly code
    print("\nGetting embedding for a single assembly code...")
    try:
        # Example assembly code string
        example_asm_code = (
            ".text\n"
            ".globl example_func\n"
            "example_func:\n"
            "    pushq %rbp\n"
            "    movq %rsp, %rbp\n"
            "    movl $0, %eax\n"
            "    popq %rbp\n"
            "    ret\n"
        )
        
        result = get_embedding(example_asm_code)
        print(f"Embedding (first few values): {result['embeddings'][0][:5]}...")
    except Exception as e:
        print(f"Error: {e}")
    
    # # 3. Example: Get embeddings for a batch of assembly codes
    # print("\nGetting embeddings for a batch of assembly codes...")
    # try:
    #     # Example assembly code strings
    #     example_asm_codes = [
    #         (
    #             ".text\n"
    #             ".globl func2\n"
    #             "func2:\n"
    #             "    pushq %rbp\n"
    #             "    movq %rsp, \n"
    #             "    movl $2, %eax\n"
    #             "    popq %rbp\n"
    #             "    ret\n"
    #         ),
    #         (
    #             ".text\n"
    #             ".globl func1\n"
    #             "func1:\n"
    #             "    pushq %rbp\n"
    #             "    movq %rsp, %rbp\n"
    #             "    movl $1, %eax\n"
    #             "    popq %rbp\n"
    #             "    ret\n"
    #         )
    #     ]
        
    #     result = get_embeddings_batch(example_asm_codes)
        
        
    except Exception as e:
        print(f"Error: {e}")
    