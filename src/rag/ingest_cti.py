"""
Ingest Cyber Threat Intelligence (CTI) feeds into the Guardian Agent Knowledge Base.
Supports MITRE ATLAS (JSON/YAML), MITRE ATT&CK (STIX JSON), and CISA KEV (CSV).
"""

from __future__ import annotations

import csv
import datetime
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from tqdm import tqdm

from src.rag.knowledge_base import Document, KnowledgeBase

logger = logging.getLogger(__name__)

BATCH_SIZE = 500


def _extract_attack_patterns(
    data: Any, source: str, ai_relevant: bool
) -> List[Document]:
    """Extract attack-pattern objects from a STIX bundle or raw list."""
    objects: List[Dict[str, Any]] = []

    if isinstance(data, dict):
        objects = data.get("objects", [])
    elif isinstance(data, list):
        objects = data

    documents: List[Document] = []

    for obj in objects:
        if not isinstance(obj, dict):
            continue
        if obj.get("type") != "attack-pattern":
            continue

        ext_id = None
        for ref in obj.get("external_references", []):
            if isinstance(ref, dict) and ref.get("external_id"):
                ext_id = ref.get("external_id")
                break

        technique_id = ext_id or obj.get("id", "")
        name = obj.get("name", "").strip()
        desc = obj.get("description", "").strip()

        tactics_list = [
            phase.get("phase_name", "").strip()
            for phase in obj.get("kill_chain_phases", [])
            if isinstance(phase, dict) and phase.get("phase_name")
        ]
        tactics = ", ".join(tactics_list)

        text = f"{name}. {desc}" if desc else f"{name}."
        metadata = {
            "source": source,
            "technique_id": technique_id,
            "tactic": tactics,
            "ai_relevant": ai_relevant,
        }

        documents.append(Document(page_content=text, metadata=metadata))

    return documents


def ingest_mitre_atlas(json_path: str, kb: KnowledgeBase) -> int:
    """
    Ingest MITRE ATLAS threat intelligence file (.yaml, .yml, or .json) into the knowledge base.
    - If .json: falls back to legacy STIX bundle behavior.
    - If .yaml or .yml: parses YAML matrices and techniques.
    """
    logger.info("Starting ingestion of MITRE ATLAS file: %s", json_path)
    path = Path(json_path)

    if not path.is_file():
        logger.warning("MITRE ATLAS file not found: %s", json_path)
        return 0

    ext = path.suffix.lower()
    if ext not in (".yaml", ".yml", ".json"):
        logger.warning("Unsupported file extension for MITRE ATLAS: %s", json_path)
        return 0

    documents: List[Document] = []

    if ext == ".json":
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
        except Exception as exc:
            logger.warning("Failed to parse MITRE ATLAS JSON from %s: %s", json_path, exc)
            return 0
        documents = _extract_attack_patterns(data, source="MITRE_ATLAS", ai_relevant=True)
    else:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                data = yaml.safe_load(f)
        except Exception as exc:
            logger.warning("Failed to parse MITRE ATLAS YAML from %s: %s", json_path, exc)
            return 0

        if not isinstance(data, dict):
            logger.warning("MITRE ATLAS YAML data in %s is not a dictionary", json_path)
            return 0

        matrices = data.get("matrices", [])
        if not isinstance(matrices, list):
            matrices = []

        for matrix in matrices:
            if not isinstance(matrix, dict):
                continue

            # Build tactic_id -> tactic_name map from matrix tactics
            tactic_map: Dict[str, str] = {}
            raw_tactics = matrix.get("tactics", [])
            if isinstance(raw_tactics, list):
                for tac in raw_tactics:
                    if isinstance(tac, dict) and "id" in tac and "name" in tac:
                        tactic_map[str(tac["id"])] = str(tac["name"])

            techniques = matrix.get("techniques", [])
            if not isinstance(techniques, list):
                continue

            for t in techniques:
                if not isinstance(t, dict):
                    continue
                # Skip techniques whose object-type is not "technique" if that key exists
                if "object-type" in t and t.get("object-type") != "technique":
                    continue

                t_id = t.get("id", "")
                id_str = "atlas:" + str(t_id)
                name = str(t.get("name", "") or "").strip()
                desc = str(t.get("description", "") or "").strip()
                raw_tac = t.get("tactics", []) or []
                tac_names = [tactic_map.get(x, x) for x in raw_tac]
                tactic = ", ".join(tac_names)
                maturity = t.get("maturity", "")
                text = f"{name}. {desc}" if desc else f"{name}."
                metadata: Dict[str, Any] = {
                    "source": "MITRE_ATLAS",
                    "technique_id": t.get("id", ""),
                    "tactic": tactic,
                    "ai_relevant": True,
                    "maturity": maturity,
                }

                # Convert any datetime.date to ISO string before adding to metadata
                for date_key in ("created_date", "modified_date"):
                    if date_key in t and t[date_key] is not None:
                        val = t[date_key]
                        metadata[date_key] = (
                            val.isoformat()
                            if isinstance(val, (datetime.date, datetime.datetime))
                            else str(val)
                        )

                for k, v in list(metadata.items()):
                    if isinstance(v, (datetime.date, datetime.datetime)):
                        metadata[k] = v.isoformat()

                documents.append(Document(page_content=text, metadata=metadata))

    if not documents:
        logger.warning("No attack-pattern or techniques found in %s", json_path)
        return 0

    total_added = 0
    for i in tqdm(
        range(0, len(documents), BATCH_SIZE),
        desc=f"Ingesting {path.name}",
        unit="batch",
        leave=False,
    ):
        batch = documents[i : i + BATCH_SIZE]
        total_added += kb.add_documents(batch)

    logger.info("Finished MITRE ATLAS ingestion. Added %d documents.", total_added)
    return total_added


def ingest_mitre_attack(json_path: str, kb: KnowledgeBase) -> int:
    """
    Ingest MITRE ATT&CK Enterprise STIX JSON file into the knowledge base.
    """
    logger.info("Starting ingestion of MITRE ATT&CK file: %s", json_path)
    path = Path(json_path)

    if not path.is_file():
        logger.warning("MITRE ATT&CK file not found: %s", json_path)
        return 0

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except Exception as exc:
        logger.error("Failed to parse MITRE ATT&CK JSON from %s: %s", json_path, exc)
        return 0

    documents = _extract_attack_patterns(data, source="MITRE_ATTACK", ai_relevant=False)
    if not documents:
        logger.info("No attack-pattern techniques found in %s", json_path)
        return 0

    total_added = 0
    for i in tqdm(
        range(0, len(documents), BATCH_SIZE),
        desc=f"Ingesting {path.name}",
        unit="batch",
        leave=False,
    ):
        batch = documents[i : i + BATCH_SIZE]
        total_added += kb.add_documents(batch)

    logger.info("Finished MITRE ATT&CK ingestion. Added %d documents.", total_added)
    return total_added


def ingest_cisa_kev(csv_path: str, kb: KnowledgeBase) -> int:
    """
    Ingest CISA Known Exploited Vulnerabilities (KEV) CSV into the knowledge base.
    Matches required headers case-insensitively.
    """
    logger.info("Starting ingestion of CISA KEV CSV: %s", csv_path)
    path = Path(csv_path)

    if not path.is_file():
        logger.warning("CISA KEV file not found: %s", csv_path)
        return 0

    documents: List[Document] = []

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                lower_row = {
                    (k.strip().lower() if k else ""): (v.strip() if v else "")
                    for k, v in row.items()
                }

                cve_id = lower_row.get("cveid", "")
                vendor = lower_row.get("vendorproject", "")
                product = lower_row.get("product", "")
                vuln_name = lower_row.get("vulnerabilityname", "")
                short_desc = lower_row.get("shortdescription", "")
                date_added = lower_row.get("dateadded", "")
                due_date = lower_row.get("duedate", "")

                text = f"{vendor} {product}: {vuln_name}. {short_desc}".strip()
                metadata = {
                    "source": "CISA_KEV",
                    "cve_id": cve_id,
                    "vendor": vendor,
                    "product": product,
                    "date_added": date_added,
                    "due_date": due_date,
                }

                documents.append(Document(page_content=text, metadata=metadata))
    except Exception as exc:
        logger.error("Failed to read CISA KEV CSV %s: %s", csv_path, exc)
        return 0

    if not documents:
        logger.info("No records parsed from CISA KEV file %s", csv_path)
        return 0

    total_added = 0
    for i in tqdm(
        range(0, len(documents), BATCH_SIZE),
        desc=f"Ingesting {path.name}",
        unit="batch",
        leave=False,
    ):
        batch = documents[i : i + BATCH_SIZE]
        total_added += kb.add_documents(batch)

    logger.info("Finished CISA KEV ingestion. Added %d documents.", total_added)
    return total_added


def ingest_all(cti_dir: str, kb: Optional[KnowledgeBase] = None) -> Dict[str, int]:
    """
    Ingest all CTI files found within the given root directory.
    Searches for:
      - mitre_atlas/*.json, mitre_atlas/*.yaml, mitre_atlas/*.yml or mitre_atlas.{json,yaml,yml}
      - mitre_attack/*.json or mitre_attack.json
      - cisa_kev/*.csv or cisa_kev.csv
    """
    if kb is None:
        kb = KnowledgeBase()

    base_dir = Path(cti_dir)
    results = {"mitre_atlas": 0, "mitre_attack": 0, "cisa_kev": 0}

    # 1. MITRE ATLAS
    atlas_files: List[Path] = []
    atlas_sub = base_dir / "mitre_atlas"
    if atlas_sub.is_dir():
        for pattern in ("*.json", "*.yaml", "*.yml"):
            atlas_files.extend(sorted(atlas_sub.glob(pattern)))
    for name in ("mitre_atlas.json", "mitre_atlas.yaml", "mitre_atlas.yml"):
        single_atlas = base_dir / name
        if single_atlas.is_file():
            atlas_files.append(single_atlas)

    if atlas_files:
        for p in atlas_files:
            results["mitre_atlas"] += ingest_mitre_atlas(str(p), kb)
    else:
        logger.warning("No MITRE ATLAS files found in %s", base_dir)

    # 2. MITRE ATT&CK
    attack_files: List[Path] = []
    attack_sub = base_dir / "mitre_attack"
    if attack_sub.is_dir():
        attack_files.extend(sorted(attack_sub.glob("*.json")))
    single_attack = base_dir / "mitre_attack.json"
    if single_attack.is_file():
        attack_files.append(single_attack)

    if attack_files:
        for p in attack_files:
            results["mitre_attack"] += ingest_mitre_attack(str(p), kb)
    else:
        logger.warning("No MITRE ATT&CK files found in %s", base_dir)

    # 3. CISA KEV
    kev_files: List[Path] = []
    kev_sub = base_dir / "cisa_kev"
    if kev_sub.is_dir():
        kev_files.extend(sorted(kev_sub.glob("*.csv")))
    single_kev = base_dir / "cisa_kev.csv"
    if single_kev.is_file():
        kev_files.append(single_kev)

    if kev_files:
        for p in kev_files:
            results["cisa_kev"] += ingest_cisa_kev(str(p), kb)
    else:
        logger.warning("No CISA KEV files found in %s", base_dir)

    return results


if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    parser = argparse.ArgumentParser(description="Ingest threat intelligence into Guardian RAG Knowledge Base")
    parser.add_argument("--data-dir", default="data/cti", help="Path to CTI data directory")
    args = parser.parse_args()

    kb = KnowledgeBase()
    before = kb.count()
    result = ingest_all(args.data_dir, kb)
    after = kb.count()
    print(f"Ingested: {result}")
    print(f"KB size: {before} -> {after}")
