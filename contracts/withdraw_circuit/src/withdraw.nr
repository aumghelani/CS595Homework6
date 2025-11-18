use dep::merkle_trees::compute_merkle_root;
use dep::std::hash::pedersen_hash;

fn main(
    // PRIVATE INPUTS (prover's secrets - keep commitment hidden!)
    r: Field,               // Blinding factor from deposit
    index: Field,           // Position of commitment in tree (hidden!)
    hashpath: [Field; 8],   // Merkle path from commitment to root (hidden!)
    
    // PUBLIC INPUTS (visible on-chain)
    root: pub Field,        // Current Merkle root
    id: pub Field           // Identifier (used as nullifier to prevent double-spend)
) {
    // CONSTRAINT 1: Compute the commitment from id and r
    let commitment = pedersen_hash([id, r]);
    
    // CONSTRAINT 2: Verify that this commitment exists in the Merkle tree
    // by recomputing the root from the commitment, index, and path
    let computed_root = compute_merkle_root(commitment, index, hashpath);
    
    // CONSTRAINT 3: Verify the computed root matches the public root
    assert(root == computed_root);
}