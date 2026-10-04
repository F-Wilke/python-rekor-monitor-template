import argparse
import base64
import json
from util import extract_public_key, verify_artifact_signature
from merkle_proof import DefaultHasher, verify_consistency, verify_inclusion, compute_leaf_hash
import requests


REKOR_BASE_URL = "https://rekor.sigstore.dev/api/v1"


def get_log_entry(log_index, debug=False):
    if not isinstance(log_index, int) or log_index < 0:
        raise ValueError("log index must be a non-negative integer")

    url = f"{REKOR_BASE_URL}/log/entries"
    if debug:
        print(f"Fetching log entry {log_index} from {url}")

    response = requests.get(url, params={"logIndex": log_index}, timeout=30)
    response.raise_for_status()
    entries = response.json()
    if not isinstance(entries, dict) or len(entries) != 1:
        raise ValueError("Rekor returned an unexpected log entry response")

    entry = next(iter(entries.values()))
    if not isinstance(entry, dict):
        raise ValueError("Rekor returned an invalid log entry")
    if int(entry.get("logIndex", -1)) != log_index:
        raise ValueError("Rekor returned an entry with a different log index")
    return entry


def get_verification_proof(log_index, debug=False, entry=None):
    if not isinstance(log_index, int) or log_index < 0:
        raise ValueError("log index must be a non-negative integer")
    if entry is None:
        entry = get_log_entry(log_index, debug)

    try:
        proof = entry["verification"]["inclusionProof"]
    except (KeyError, TypeError) as error:
        raise ValueError("Rekor entry does not contain an inclusion proof") from error
    if not isinstance(proof, dict):
        raise ValueError("Rekor returned an invalid inclusion proof")
    return proof


def inclusion(log_index, artifact_filepath, debug=False):
    if not isinstance(log_index, int) or log_index < 0:
        raise ValueError("log index must be a non-negative integer")
    if not artifact_filepath:
        raise ValueError("an artifact filepath is required")

    entry = get_log_entry(log_index, debug)
    try:
        body = entry["body"]
        body_data = json.loads(base64.b64decode(body, validate=True))
        signature_data = body_data["spec"]["signature"]
        signature = base64.b64decode(signature_data["content"], validate=True)
        certificate = base64.b64decode(
            signature_data["publicKey"]["content"], validate=True
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("Rekor entry does not contain a valid hashedrekord body") from error

    public_key = extract_public_key(certificate)
    signature_valid = verify_artifact_signature(
        signature, public_key, artifact_filepath
    )
    proof = get_verification_proof(log_index, debug, entry)
    try:
        proof_index = int(proof["logIndex"])
        tree_size = int(proof["treeSize"])
        hashes = proof["hashes"]
        root_hash = proof["rootHash"]
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("Rekor returned an incomplete inclusion proof") from error
    if not isinstance(hashes, list) or not all(
        isinstance(proof_hash, str) for proof_hash in hashes
    ):
        raise ValueError("Rekor returned invalid inclusion proof hashes")
    if not isinstance(root_hash, str):
        raise ValueError("Rekor returned an invalid inclusion proof root hash")
    if proof_index < 0 or tree_size <= proof_index:
        raise ValueError("Rekor returned invalid inclusion proof index or tree size")

    leaf_hash = compute_leaf_hash(body)
    verify_inclusion(
        DefaultHasher, proof_index, tree_size, leaf_hash, hashes, root_hash, debug
    )

    print(f"Artifact signature: {'valid' if signature_valid else 'invalid'}")
    print("Rekor inclusion proof: valid")
    return signature_valid


def get_latest_checkpoint(debug=False):
    url = f"{REKOR_BASE_URL}/log"
    if debug:
        print(f"Fetching latest Rekor checkpoint from {url}")

    response = requests.get(url, timeout=30)
    response.raise_for_status()
    checkpoint = response.json()
    required_fields = ("treeID", "treeSize", "rootHash")
    if not isinstance(checkpoint, dict) or any(
        field not in checkpoint for field in required_fields
    ):
        raise ValueError("Rekor returned an incomplete checkpoint")
    return checkpoint

def consistency(prev_checkpoint, debug=False):
    if not isinstance(prev_checkpoint, dict):
        raise ValueError("previous checkpoint must be an object")
    try:
        tree_id = str(prev_checkpoint["treeID"])
        previous_size = int(prev_checkpoint["treeSize"])
        previous_root = prev_checkpoint["rootHash"]
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(
            "previous checkpoint must include treeID, treeSize, and rootHash"
        ) from error
    if not tree_id.isdigit() or previous_size < 1:
        raise ValueError("previous checkpoint has an invalid tree ID or tree size")
    if not isinstance(previous_root, str):
        raise ValueError("previous checkpoint root hash must be a string")

    latest_checkpoint = get_latest_checkpoint(debug)
    latest_tree_id = str(latest_checkpoint["treeID"])
    latest_size = int(latest_checkpoint["treeSize"])
    latest_root = latest_checkpoint["rootHash"]

    if tree_id != latest_tree_id:
        raise ValueError(
            f"checkpoint tree ID {tree_id} does not match current tree "
            f"{latest_tree_id}"
        )
    if previous_size >= latest_size:
        raise ValueError(
            "previous checkpoint must be older than the latest checkpoint "
            f"({previous_size} >= {latest_size})"
        )

    url = f"{REKOR_BASE_URL}/log/proof"
    params = {
        "firstSize": previous_size,
        "lastSize": latest_size,
        "treeID": tree_id,
    }
    if debug:
        print(f"Fetching consistency proof from {url} with {params}")
    response = requests.get(url, params=params, timeout=30)
    response.raise_for_status()
    proof = response.json()
    try:
        hashes = proof["hashes"]
        proof_root = proof["rootHash"]
    except (KeyError, TypeError) as error:
        raise ValueError("Rekor returned an incomplete consistency proof") from error
    if not isinstance(hashes, list) or not all(
        isinstance(proof_hash, str) for proof_hash in hashes
    ):
        raise ValueError("Rekor returned invalid consistency proof hashes")
    if not isinstance(proof_root, str):
        raise ValueError("Rekor returned an invalid consistency proof root hash")

    verify_consistency(
        DefaultHasher,
        previous_size,
        latest_size,
        hashes,
        previous_root,
        latest_root,
    )
    print(
        f"Checkpoint consistency: valid "
        f"({previous_size} -> {latest_size}, tree {tree_id})"
    )
    return True

def main():
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument('-d', '--debug', help='Debug mode',
                        required=False, action='store_true') # Default false
    parser.add_argument('-c', '--checkpoint', help='Obtain latest checkpoint\
                        from Rekor Server public instance',
                        required=False, action='store_true')
    parser.add_argument('--inclusion', help='Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567',
                        required=False, type=int)
    parser.add_argument('--artifact', help='Artifact filepath for verifying\
                        signature',
                        required=False)
    parser.add_argument('--consistency', help='Verify consistency of a given\
                        checkpoint with the latest checkpoint.',
                        action='store_true')
    parser.add_argument('--tree-id', help='Tree ID for consistency proof',
                        required=False)
    parser.add_argument('--tree-size', help='Tree size for consistency proof',
                        required=False, type=int)
    parser.add_argument('--root-hash', help='Root hash for consistency proof',
                        required=False)
    args = parser.parse_args()
    if args.debug:
        debug = True
        print("enabled debug mode")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json
        checkpoint = get_latest_checkpoint(debug)
        print(json.dumps(checkpoint, indent=4))
    if args.inclusion:
        inclusion(args.inclusion, args.artifact, debug)
    if args.consistency:
        if not args.tree_id:
            print("please specify tree id for prev checkpoint")
            return
        if not args.tree_size:
            print("please specify tree size for prev checkpoint")
            return
        if not args.root_hash:
            print("please specify root hash for prev checkpoint")
            return

        prev_checkpoint = {}
        prev_checkpoint["treeID"] = args.tree_id
        prev_checkpoint["treeSize"] = args.tree_size
        prev_checkpoint["rootHash"] = args.root_hash

        consistency(prev_checkpoint, debug)

if __name__ == "__main__":
    main()



"""sample response (log/entrie):
{
  "108e9186e8c5677a77b9d4862628ad0fa320bdbb16505925ff0ee8bbd7b20625ab1ecd97bf1b62a2": {
    "body": "{"apiVersion":"0.0.1","kind":"hashedrekord","spec":{"data":{"hash":{"algorithm":"sha256","value":"61b166962815d14d966f70c324d72678e0264f5e837b353d36db0532d4a6896a"}},"signature":{"content":"MEUCIAzbAOi3w1Xc5fLvpbgk3gU+LpgdrO7ju1OiQC1UsoD8AiEA0uNrzsQrxU67rM2EQhr23LreznAtXIWxXmD9Pd0Oxh8=","publicKey":{"content":"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURJekNDQXFtZ0F3SUJBZ0lVYTFHVnBwVyt1NEhneUhuVFNLQUo2QTlxL2NVd0NnWUlLb1pJemowRUF3TXcKTnpFVk1CTUdBMVVFQ2hNTWMybG5jM1J2Y21VdVpHVjJNUjR3SEFZRFZRUURFeFZ6YVdkemRHOXlaUzFwYm5SbApjbTFsWkdsaGRHVXdIaGNOTWpZeE1EQTBNVGN6TnpVeFdoY05Nall4TURBME1UYzBOelV4V2pBQU1Ga3dFd1lICktvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVFRTV5cmJWQWtqaC9JTEFLV0t6N0NxOEI2a1BQalVrcGVMeisKNUlNRG9jZFJuT2YwSWlwcUo2aGhXVkVZYnpIQzhIOHBXZHozOFl4a2xqQkhvVGJXUzZPQ0FjZ3dnZ0hFTUE0RwpBMVVkRHdFQi93UUVBd0lIZ0RBVEJnTlZIU1VFRERBS0JnZ3JCZ0VGQlFjREF6QWRCZ05WSFE0RUZnUVVzanRPCmYzTGdPc3BCN3M1bHlVYmQ3ZGV6d0RNd0h3WURWUjBqQkJnd0ZvQVUzOVBwejFZa0VaYjVxTmpwS0ZXaXhpNFkKWkQ4d0hBWURWUjBSQVFIL0JCSXdFSUVPWm5jeU5EWXlRRzU1ZFM1bFpIVXdLUVlLS3dZQkJBR0R2ekFCQVFRYgphSFIwY0hNNkx5OWhZMk52ZFc1MGN5NW5iMjluYkdVdVkyOXRNQ3NHQ2lzR0FRUUJnNzh3QVFnRUhRd2JhSFIwCmNITTZMeTloWTJOdmRXNTBjeTVuYjI5bmJHVXVZMjl0TUZzR0Npc0dBUVFCZzc4d0FSZ0VUUXhMUTJoVmVFMUUKUlRSTmFrVjVUbnBGZVU5RVJURk5hbFY2VGxSTmVFOVVSVk5JTW1nd1pFaENlazlwVlhsU2FWVjVVbTFHYWxreQpPVEZpYmxKNlRHMWtkbUl5WkhOYVV6VnFZakl3TUlHSkJnb3JCZ0VFQWRaNUFnUUNCSHNFZVFCM0FIVUEzVDB3CmFzYkhFVEpqR1I0Y21XYzNBcUpLWHJqZVBLMy9oNHB5Z0M4cDdvNEFBQUdoQi81V3ZnQUFCQU1BUmpCRUFpQnEKT2x3aDhnNEhVRVFDc3VCZHBYYkJJa09qa2NPcWFDd1hGZzFUdFJSZGhnSWdMZ2FkcU1ZOCt5MTRheTlHWlJKdgppQnp1Yk00U2gyd0JpRVYyMFgxbjJxVXdDZ1lJS29aSXpqMEVBd01EYUFBd1pRSXhBSjArSitmb1hMNUZlRkRTCld2ZWlRcDNoZTVHVEZUOGo0Z0U2VVVKdjNNZXcyWlBid0dFemhzRjhHOHNvZGx6TnJRSXdCVHR5L3BRRUh2eVoKNVBRTGNKYXZDRW9KZGNtRUMxR1BxWWQ1OGpNNTJKNUdmeGxJQzcwaDY5L3FsVi8zb0tHVwotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=="}}}}",
    "integratedTime": 1791135471,
    "logID": "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
    "logIndex": 3078143996,
    "verification": {
      "inclusionProof": {
        "checkpoint": "rekor.sigstore.dev - 1193050959916656506\n2956252108\nuYz3l/u28D7kOaTLDSF2s/ZSBjOe5z7eruUEz68raQA=\n\n— rekor.sigstore.dev wNI9ajBFAiB/3Tjnu9r3MafydqwU6wT/kykLdP7QnpKt5j/XmqyeFgIhANA9VwVie0lAXT6Fy8YbFxwZ1yiVMDGn8LlaH5nZH/wE\n",
        "hashes": [
          "50f876a41c2f31760202ecd97ac0c3242ea05a01a3882f5c50e36a46e1c04825",
          "70de64d3ef4552aba918d11c4e97be39b75cfe51fb5fe1d64bc8b7ed38181827",
          "f7ff429fde9da2baecb77a0cab8a28759c247bbcc2f6c9d0b1ef1b4f5d4eef0f",
          "fdf6e27fbd7eea84fa589250f5464059440daa84ad8f158a887f922aedd3420a",
          "84e344a187057ff54f1f6c7de25e2fb9621178be5a5886c4a16cb665fa2c1b74",
          "f27ad1f94ed6d071a1de1d3b1f43688ede897d05c96646b4371cff100caa95e2",
          "20e7e0f38b4d5ecee5763b519e527c5669fa8e4abc6283b71ef0904a335e5f20",
          "ac4328d6eb6c98f8f807c20d6e0b617e21c31cefe706dd43b62f8510b04b0885",
          "ac8bd1d2579a9d27e1daa57002429fdba8552cc116ed931ddbe1b442984df6d2",
          "efdfa09a8d787a9d1ed6d8796dbf705e79dea65979ca1d9c05f552fd828913e1",
          "5150f62f563eb54621c877976c81e0050ddf545ad61490203a17cb6ca5ebf0d2",
          "d46d9d2fa84070aa99a22977d131602aeb58349fe44ea4c79ea9835c8b507908",
          "087c87aa56ea2f55c69f4451ae99190e6325ffe827097d6c4cf768c4f7b44a01",
          "03ebe6d3692921bcdb1c13943aee3f81b5ca7152c243c413e8c877b4492d5499",
          "77b70cffb972667189ec1e3f1983c0e1ada1c94bd94cd03896bd39dd5235e38a",
          "70cc03335a431c71b3c74fd46c1886034c9b5d911b0b451e4a89769dbb767105",
          "a45ed7adef60e5fa59fd32edd852aa510ceeee9144cfa5d03abe951593140579",
          "7b3c9598e11a6986d56b6359c0e92412a702ea722472e54986f12aa3c8118921",
          "6ee7c25838b0f331792ff012cde6346981cfd4b92e5d7a242ad65d9802cf841e",
          "36539c96576628f035b4c288b24a87030b900d81e9df5630a4af8e38cacc71c7",
          "ab1cc76a7033cf9ed20dd9897b407b6c92bbd8d4c805bc043060412af0ce44ec",
          "c47fc30ac78b1ebf5e2a8613f2ab0e4592bbcd5744198587b95b6c56b0fde706"
        ],
        "logIndex": 2956239734,
        "rootHash": "b98cf797fbb6f03ee439a4cb0d2176b3f65206339ee73edeaee504cfaf2b6900",
        "treeSize": 2956252108
      },
      "signedEntryTimestamp": "MEQCID6zGjee4fMIhe1loIU+zkLfVeQ9OuMBHz0B+wuHD6XiAiAGqpetHaRRwyseXu9C+34xKOvU4l++JIvMMXK7TQf3qw=="
    }
  }
}
"""