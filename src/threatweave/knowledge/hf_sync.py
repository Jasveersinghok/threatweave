import os
import zipfile
from pathlib import Path
import httpx
import logging
import streamlit as st

logger = logging.getLogger(__name__)

# NOTE: The user must upload data.zip to HuggingFace (or any direct link) and paste the URL here.
# Example: "https://huggingface.co/datasets/yourusername/threatweave-data/resolve/main/data.zip"
HF_DATASET_URL = os.environ.get("HF_DATASET_URL", "")

def sync_from_huggingface() -> None:
    """Download and extract pre-embedded data from HuggingFace if missing."""
    data_dir = Path("data")
    qdrant_dir = data_dir / "qdrant"
    techniques_file = data_dir / "attack" / "techniques.json"

    # If the data already exists (like on local dev), do nothing.
    if qdrant_dir.exists() and techniques_file.exists():
        return

    if not HF_DATASET_URL:
        st.warning("⚠️ Qdrant database is missing and HF_DATASET_URL is not set in secrets! Hybrid search will fail.")
        return

    zip_path = data_dir / "data.zip"
    
    with st.spinner("Downloading pre-computed AI embeddings from HuggingFace (this only happens once)..."):
        data_dir.mkdir(parents=True, exist_ok=True)
        try:
            logger.info("Downloading dataset from %s", HF_DATASET_URL)
            with httpx.stream("GET", HF_DATASET_URL, follow_redirects=True) as r:
                r.raise_for_status()
                with open(zip_path, "wb") as f:
                    for chunk in r.iter_bytes(chunk_size=8192):
                        f.write(chunk)
            
            logger.info("Extracting %s", zip_path)
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(data_dir)
                
            # If the zip file contained a "data" folder, it extracted to data/data/
            # Let's move it up.
            import shutil
            nested_data = data_dir / "data"
            if nested_data.exists() and nested_data.is_dir():
                for item in nested_data.iterdir():
                    shutil.move(str(item), str(data_dir / item.name))
                nested_data.rmdir()
            
            # Clean up the zip file
            zip_path.unlink(missing_ok=True)
            st.success("✅ Dataset successfully synced from HuggingFace!")
            
        except Exception as e:
            logger.error("Failed to sync from HuggingFace: %s", e)
            st.error(f"Failed to download dataset from HuggingFace: {e}")
