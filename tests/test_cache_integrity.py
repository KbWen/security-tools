import os
import json
import hashlib
from ghostcheck.checks.hallucination import HallucinationChecker

def test_cache_integrity_failure(tmp_path):
    cache_file = tmp_path / "hallucination.json"
    
    # Create valid cache
    data = {"PyPI:requests": {"timestamp": "2026-03-18T00:00:00", "data": "OK"}}
    # Calculate integrity
    hasher = hashlib.sha256(json.dumps(data, sort_keys=True).encode())
    data['integrity'] = hasher.hexdigest()
    
    with open(cache_file, 'w') as f:
        json.dump(data, f)
        
    # Verify it loads
    checker = HallucinationChecker()
    checker.cache_file = str(cache_file)
    checker._load_cache()
    # Note: data was mutated by pop('integrity') in _load_cache logic
    # so we compare with the "clean" state
    expected = {"PyPI:requests": {"timestamp": "2026-03-18T00:00:00", "data": "OK"}}
    assert checker.cache == expected
    
    # Corrupt the cache manually
    with open(cache_file, 'w') as f:
        data_corrupt = expected.copy()
        data_corrupt['PyPI:requests'] = {"timestamp": "2026-03-18T00:00:00", "data": "CORRUPTED"}
        # Add the old (now incorrect) integrity hash
        data_corrupt['integrity'] = hasher.hexdigest()
        json.dump(data_corrupt, f)
        
    # Should detect failure and reset cache
    checker._load_cache()
    assert checker.cache == {}
