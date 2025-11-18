use dep::merkle_trees::compute_merkle_root;
use dep::std::hash::pedersen_hash;

fn main(
    // PRIVATE INPUTS (prover's secrets)
    id: Field,              // Random identifier
    r: Field,               // Random blinding factor
    oldPath: [Field; 8],    // Merkle path from old empty leaf to old root
    
    // PUBLIC INPUTS (visible on-chain)
    oldRoot: pub Field,     // Merkle root before insertion
    newRoot: pub Field,     // Merkle root after insertion
    commitment: pub Field,  // The commitment being deposited
    index: pub Field        // Position in tree where commitment is inserted
) {
    // CONSTRAINT 1: Verify that commitment equals pedersen_hash([id, r])
    let computed_commitment = pedersen_hash([id, r]);
    assert(commitment == computed_commitment);
    
    // CONSTRAINT 2: Verify the old Merkle path is valid for oldRoot
    // The empty leaf value (Pedersen hash of 0)
    let empty_leaf = 0x2df8b940e5890e4e1377e05373fae69a1d754f6935e6a780b666947431f2cdcd;
    let old_computed_root = compute_merkle_root(empty_leaf, index, oldPath);
    assert(oldRoot == old_computed_root);
    
    // CONSTRAINT 3: Verify the new Merkle root is correct after inserting commitment
    // We use the same path structure, but now with the commitment as the leaf
    let new_computed_root = compute_merkle_root(commitment, index, oldPath);
    assert(newRoot == new_computed_root);
}