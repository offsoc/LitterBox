# app/analyzers/fuzzy.py

import pyssdeep
import json
import os
import hashlib
import configparser
import zlib
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
import binascii

class BlockData:
    def __init__(self, raw_data: bytes, start_offset: int):
        self.raw_data = raw_data
        self.start_offset = start_offset
        self.length = len(raw_data)

    def _create_hex_dump(self) -> str:
        """Only created when displaying results"""
        hex_lines = []
        for i in range(0, self.length, 16):
            chunk = self.raw_data[i:i + 16]
            hex_values = ' '.join(f'{b:02x}' for b in chunk)
            hex_values = hex_values.ljust(48)
            hex_lines.append(f"{self.start_offset + i:08x}  {hex_values}")
        return '\n'.join(hex_lines)

    def _create_ascii_repr(self) -> str:
        """Only created when displaying results"""
        ascii_lines = []
        for i in range(0, self.length, 16):
            chunk = self.raw_data[i:i + 16]
            ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            ascii_lines.append(ascii_str)
        return '\n'.join(ascii_lines)

    def to_dict(self) -> Dict[str, Any]:
        """Store absolute minimum in DB, converting bytes to base64 string"""
        compressed = zlib.compress(self.raw_data)
        return {
            "o": self.start_offset,  # Shortened key names
            "d": binascii.b2a_base64(compressed).decode('ascii').strip()  # Compress and convert to base64
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BlockData':
        """Reconstruct from minimal data"""
        compressed = binascii.a2b_base64(data["d"])  # Convert base64 back to bytes
        raw_data = zlib.decompress(compressed)
        return cls(raw_data, data["o"])

class BlockMetadata:
    def __init__(self, index: int, block_size: int, hash_value: str, data: BlockData):
        self.index = index
        self.start_offset = data.start_offset
        self.end_offset = data.start_offset + data.length
        self.hash = hash_value
        self.data = data

    def to_dict(self) -> Dict[str, Any]:
        return {
            "i": self.index,  # Shortened key names
            "h": self.hash,
            "d": self.data.to_dict()
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any], block_size: int) -> 'BlockMetadata':
        block_data = BlockData.from_dict(data["d"])
        return cls(data["i"], block_size, data["h"], block_data)

class FileMetadata:
    def __init__(self, path: str, md5: str, file_size: int, blocks: List[BlockMetadata]):
        self.path = path
        self.md5 = md5
        self.file_size = file_size
        self.blocks = blocks
        self.date_added = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "p": self.path,  # Shortened key names
            "m": self.md5,
            "s": self.file_size,
            "b": [b.to_dict() for b in self.blocks],
            "d": self.date_added
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any], block_size: int) -> 'FileMetadata':
        blocks = [BlockMetadata.from_dict(b, block_size) for b in data["b"]]
        instance = cls(data["p"], data["m"], data["s"], blocks)
        instance.date_added = data.get("d", datetime.now().isoformat())
        return instance

class MatchingRegion:
    def __init__(self):
        self.source_start = 0
        self.target_start = 0
        self.length = 0
        self.total_similarity = 0
        self.blocks = 0
        self.source_data: List[BlockData] = []
        self.target_data: List[BlockData] = []

    def add_block(self, source_block: BlockMetadata, target_block: BlockMetadata, similarity: float):
        if self.blocks == 0:
            self.source_start = source_block.start_offset
            self.target_start = target_block.start_offset
            self.length = source_block.data.length
        else:
            self.length += source_block.data.length

        self.source_data.append(source_block.data)
        self.target_data.append(target_block.data)
        self.total_similarity += similarity
        self.blocks += 1

    @property
    def avg_similarity(self) -> float:
        return self.total_similarity / self.blocks if self.blocks > 0 else 0

    def to_dict(self) -> Dict[str, Any]:
        """When converting for display, create the ASCII and hex representations"""
        results = {
            "source_start": self.source_start,
            "target_start": self.target_start,
            "length": self.length,
            "avg_similarity": self.avg_similarity,
            "blocks": self.blocks,
            "source_data": [],
            "target_data": []
        }
        
        # Only create display data when needed
        for src_data in self.source_data:
            results["source_data"].append({
                "ascii_repr": src_data._create_ascii_repr(),
                "hex_dump": src_data._create_hex_dump()
            })
            
        for tgt_data in self.target_data:
            results["target_data"].append({
                "ascii_repr": tgt_data._create_ascii_repr(),
                "hex_dump": tgt_data._create_hex_dump()
            })
            
        return results

class GitRepoInfo:
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        
    def get_remote_url(self) -> Optional[str]:
        """Extract the remote URL from .git/config"""
        try:
            git_config_path = self.repo_path / '.git' / 'config'
            if not git_config_path.exists():
                return None
                
            config = configparser.ConfigParser()
            config.read(git_config_path)
            
            for section in config.sections():
                if section.startswith('remote "origin"'):
                    url = config[section].get('url', '')
                    if url.startswith('git@github.com:'):
                        url = f"https://github.com/{url.split('git@github.com:')[1]}"
                    if url.endswith('.git'):
                        url = url[:-4]
                    return url
            return None
        except Exception:
            return None

class FuzzyHashAnalyzer:
    def __init__(self, config, logger=None):
        self.config = config
        self.logger = logger
        self.block_size = 4096
        # Get the base path and create full db path
        fuzzy_base = config['analysis']['doppelganger']['db']['path']
        fuzzy_dir = config['analysis']['doppelganger']['db']['fuzzyhash']
        self.db_path = os.path.join(fuzzy_base, fuzzy_dir, 'FuzzyHash.db')
        self.extensions = [f".{ext}" for ext in config['analysis']['doppelganger']['db'].get('fuzzy_extensions', [])]
        self.db = self._load_db()

    def _save_db(self):
        """Save with maximum compression"""
        data = {
            "sources": {
                source: {
                    "f": {  # Shortened key names
                        path: file_data.to_dict()
                        for path, file_data in source_data["files"].items()
                    },
                    "u": source_data["last_updated"]
                }
                for source, source_data in self.db["sources"].items()
            }
        }
        
        # Convert to JSON with minimal formatting and compress
        json_str = json.dumps(data, separators=(',', ':'))
        compressed = zlib.compress(json_str.encode('utf-8'), level=9)
        
        with open(self.db_path, 'wb') as f:
            f.write(compressed)

    def _load_db(self) -> Dict:
        """Load compressed database"""
        empty_db = {"sources": {}}
        
        if not os.path.exists(self.db_path):
            if self.logger:
                self.logger.debug(f"Database file {self.db_path} not found. Creating new database.")
            self._save_empty_db()
            return empty_db
            
        try:
            with open(self.db_path, 'rb') as f:
                compressed_data = f.read()
                
            if not compressed_data:
                return empty_db
                
            # Decompress and parse
            json_str = zlib.decompress(compressed_data).decode('utf-8')
            data = json.loads(json_str)
            
            # Convert shortened keys back
            converted = {"sources": {}}
            for source, sdata in data["sources"].items():
                converted["sources"][source] = {
                    "files": {},
                    "last_updated": sdata["u"]
                }
                for path, fdata in sdata["f"].items():
                    converted["sources"][source]["files"][path] = FileMetadata.from_dict(
                        fdata, self.block_size
                    )
            return converted
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error loading database: {e}")
            self._save_empty_db()
            return empty_db

    def _save_empty_db(self):
        """Initialize empty compressed database"""
        empty_data = zlib.compress(json.dumps({"sources": {}}).encode('utf-8'), level=9)
        with open(self.db_path, 'wb') as f:
            f.write(empty_data)

    def _compute_md5(self, file_path: str) -> str:
        """Compute MD5 hash of a file"""
        md5_hash = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hash.update(chunk)
        return md5_hash.hexdigest()

    def _create_blocks(self, file_path: str) -> List[BlockMetadata]:
        """Create block metadata with content"""
        blocks = []
        with open(file_path, 'rb') as f:
            index = 0
            while True:
                data = f.read(self.block_size)
                if not data:
                    break
                try:
                    hash_value = pyssdeep.fuzzy_hash_buf(data, len(data))
                    block_data = BlockData(data, index * self.block_size)
                    blocks.append(BlockMetadata(index, self.block_size, hash_value, block_data))
                    index += 1
                except Exception as e:
                    if self.logger:
                        self.logger.warning(f"Could not compute fuzzy hash for block {index}: {str(e)}")
        return blocks

    def compute_file_metadata(self, file_path: str) -> FileMetadata:
        """Compute complete file metadata including blocks"""
        md5 = self._compute_md5(file_path)
        file_size = os.path.getsize(file_path)
        blocks = self._create_blocks(file_path)
        return FileMetadata(file_path, md5, file_size, blocks)

    def _compare_blocks(self, blocks1: List[BlockMetadata], blocks2: List[BlockMetadata]) -> Dict:
        """Compare blocks and find matching regions"""
        matching_regions = []
        current_region = None
        overall_similarity = 0
        total_comparisons = min(len(blocks1), len(blocks2))

        for b1 in blocks1:
            best_match = {
                "block": None,
                "similarity": 0
            }

            for b2 in blocks2:
                similarity = pyssdeep.fuzzy_compare(b1.hash, b2.hash)
                if similarity > best_match["similarity"]:
                    best_match["similarity"] = similarity
                    best_match["block"] = b2

            if best_match["similarity"] > 0:
                if current_region is None:
                    current_region = MatchingRegion()
                
                b2 = best_match["block"]
                if (current_region.blocks > 0 and
                    b1.start_offset == current_region.source_start + current_region.length and
                    b2.start_offset == current_region.target_start + current_region.length):
                    # Extend current region
                    current_region.add_block(b1, b2, best_match["similarity"])
                else:
                    # Start new region
                    if current_region.blocks > 0:
                        matching_regions.append(current_region)
                    current_region = MatchingRegion()
                    current_region.add_block(b1, b2, best_match["similarity"])
                
                overall_similarity += best_match["similarity"]

        if current_region and current_region.blocks > 0:
            matching_regions.append(current_region)

        return {
            "overall_similarity": (overall_similarity / total_comparisons) if total_comparisons > 0 else 0,
            "matching_regions": [region.to_dict() for region in matching_regions],
            "total_regions": len(matching_regions)
        }

    def find_git_root(self, path: Path) -> Optional[Tuple[str, Path]]:
        """Find Git repository information"""
        current = path
        while current != current.parent:
            if (current / '.git').is_dir():
                repo_info = GitRepoInfo(current)
                remote_url = repo_info.get_remote_url()
                if remote_url:
                    # Convert git URLs to HTTPS format if needed
                    if remote_url.startswith('git@github.com:'):
                        remote_url = f"https://github.com/{remote_url.split('git@github.com:')[1]}"
                    if remote_url.endswith('.git'):
                        remote_url = remote_url[:-4]
                    return remote_url, current
            current = current.parent
        return "Private Collection", path.parent

    def create_db_from_folder(self, folder_path: str, extensions: List[str] = None) -> Dict:
        """Create database from folder with specific file extensions"""
        try:
            folder = Path(folder_path)
            if not folder.exists():
                raise Exception(f"Folder not found: {folder_path}")

            # Use provided extensions or fall back to configured extensions
            extensions_to_use = extensions if extensions is not None else self.extensions
            
            processed = 0
            skipped = 0
            sources_found = set()
            
            for file_path in folder.rglob('*'):
                if file_path.is_file():
                    if extensions_to_use and file_path.suffix.lower() not in extensions_to_use:
                        skipped += 1
                        continue
                    
                    if '.git' in file_path.parts:
                        skipped += 1
                        continue
                    
                    try:
                        repo_info = self.find_git_root(file_path)
                        if not repo_info:
                            print(f"Warning: No git repository found for {file_path}")
                            skipped += 1
                            continue
                            
                        source_url, repo_root = repo_info
                        source = source_url
                        
                        if source not in self.db["sources"]:
                            self.db["sources"][source] = {
                                "files": {},
                                "last_updated": datetime.now().isoformat()
                            }
                        file_metadata = self.compute_file_metadata(str(file_path))
                        rel_path = str(file_path.relative_to(folder))
                        
                        self.db["sources"][source]["files"][rel_path] = file_metadata
                        processed += 1
                        sources_found.add(source)
                        
                        if self.logger:
                            self.logger.debug(f"Processed: {rel_path}")
                            
                    except Exception as e:
                        if self.logger:
                            self.logger.error(f"Error processing {file_path}: {str(e)}")
                        skipped += 1

            self._save_db()
            return {
                "processed": processed,
                "skipped": skipped,
                "total": processed + skipped,
                "sources": list(sources_found)
            }

        except Exception as e:
            if self.logger:
                self.logger.error(f"Database creation failed: {str(e)}")
            raise Exception(f"Database creation failed: {str(e)}")

    def analyze_files(self, file_paths: List[str], threshold: int = 1) -> List[Dict]:
        """Analyze files against the database - returns only top 3 matches per file"""
        results = []
        batch_size = 10
        
        for i in range(0, len(file_paths), batch_size):
            batch = file_paths[i:i + batch_size]
            batch_metadata = []
            
            for file_path in batch:
                try:
                    metadata = self.compute_file_metadata(file_path)
                    batch_metadata.append((file_path, metadata))
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"Error processing {file_path}: {str(e)}")
                    continue
            
            for file_path, current_metadata in batch_metadata:
                matches = []
                for source_url, source_data in self.db["sources"].items():
                    for rel_path, file_data in source_data["files"].items():
                        comparison = self._compare_blocks(current_metadata.blocks, file_data.blocks)
                        
                        if comparison["overall_similarity"] >= threshold:
                            match = {
                                "source": source_url,
                                "file": rel_path,
                                "overall_similarity": comparison["overall_similarity"],
                                "md5": file_data.md5,
                                "matching_regions": comparison["matching_regions"],
                                "total_regions": comparison["total_regions"],
                                "target_size": file_data.file_size,
                                "date_added": file_data.date_added
                            }
                            matches.append(match)

                # Sort matches by similarity and take top 3
                sorted_matches = sorted(matches, key=lambda x: x["overall_similarity"], reverse=True)[:3]

                result = {
                    "file": os.path.basename(file_path),
                    "path": file_path,
                    "md5": current_metadata.md5,
                    "file_size": current_metadata.file_size,
                    "total_blocks": len(current_metadata.blocks),
                    "matches": sorted_matches,  # Now contains only top 3
                    "total_matches": len(matches)  # Keep total count of all matches
                }
                results.append(result)
                
        return results

    def get_db_stats(self) -> Dict[str, Any]:
        """Get comprehensive database statistics"""
        stats = {
            "total_files": 0,
            "total_size": 0,  # Total size of indexed files
            "db_size": 0,     # Size of the database file itself
            "sources": {},
            "last_updated": None
        }
        
        # Get database file size
        try:
            stats["db_size"] = os.path.getsize(self.db_path)
            stats["db_size_human"] = self._format_size(stats["db_size"])
        except (OSError, IOError) as e:
            if self.logger:
                self.logger.error(f"Error getting database file size: {e}")
            stats["db_size"] = 0
            stats["db_size_human"] = "0 B"
        
        # Count files and sources
        for source, source_data in self.db["sources"].items():
            source_stats = {
                "file_count": len(source_data["files"]),
                "last_updated": source_data["last_updated"]
            }
            
            stats["total_files"] += source_stats["file_count"]
            for file_data in source_data["files"].values():
                stats["total_size"] += file_data.file_size
            
            stats["sources"][source] = source_stats
            
            # Track most recent update
            source_date = datetime.fromisoformat(source_data["last_updated"])
            if not stats["last_updated"] or source_date > datetime.fromisoformat(stats["last_updated"]):
                stats["last_updated"] = source_data["last_updated"]
        
        stats["total_size_human"] = self._format_size(stats["total_size"])
        
        return stats

    def _format_size(self, size: int) -> str:
        """Convert bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024 or unit == 'TB':
                return f"{size:.2f} {unit}"
            size /= 1024

    def print_matching_region(self, region: Dict[str, Any], source_file: str, target_file: str) -> Dict[str, Any]:
        """Generate detailed hex and ASCII comparison of matching regions"""
        comparison_data = {
            "similarity": round(region['avg_similarity'], 2),
            "length": region['length'],
            "source_file": source_file,
            "source_range": {
                "start": f"{region['source_start']:08x}",
                "end": f"{region['source_start'] + region['length']:08x}"
            },
            "target_file": target_file,
            "target_range": {
                "start": f"{region['target_start']:08x}",
                "end": f"{region['target_start'] + region['length']:08x}"
            },
            "source_data": [],
            "target_data": []
        }

        # Process source data
        for block_data in region['source_data']:
            ascii_lines = block_data['ascii_repr'].split('\n')
            hex_lines = block_data['hex_dump'].split('\n')
            for ascii_line, hex_line in zip(ascii_lines, hex_lines):
                if set(ascii_line) != {'.'}:  # Only include lines with non-dot characters
                    comparison_data["source_data"].append({
                        "ascii": ascii_line,
                        "hex": hex_line
                    })

        # Process target data
        for block_data in region['target_data']:
            ascii_lines = block_data['ascii_repr'].split('\n')
            hex_lines = block_data['hex_dump'].split('\n')
            for ascii_line, hex_line in zip(ascii_lines, hex_lines):
                if set(ascii_line) != {'.'}:  # Only include lines with non-dot characters
                    comparison_data["target_data"].append({
                        "ascii": ascii_line,
                        "hex": hex_line
                    })

        if self.logger:
            self.logger.debug(f"Processed matching region comparison for {source_file} and {target_file}")

        return comparison_data