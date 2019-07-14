extern crate ewasm_api;
extern crate tiny_keccak;

use ewasm_api::*;

#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn main() {
    let pre_state_root = eth2::load_pre_state_root();

    // block_data in sha3hasher.yaml is 532 bytes
    // this is the size of a full branch node (16 32-byte hashes RLP encoded) in a hexary merkle-patricia-trie
    let mut block_data = eth2::acquire_block_data();

    //let mut hash = [0u8; 32];
    // initialize 200 32-byte buffers
    let mut hash_outputs = [[0u8; 32]; 200];

    let mut i = 0;
    //for i in 0u8..200 { // rust will not let me take hash_outputs[i] lol
    for output in hash_outputs.iter_mut() {
        block_data[0] = i; // mutate first byte of the block data just to get a different hash for the result
        i = i + 1;

        //tiny_keccak::Keccak::keccak256(&block_data[..], &mut hash_outputs[i]);
        tiny_keccak::Keccak::keccak256(&block_data[..], output);
    }

    // No updates were made to the state
    let post_state_root = pre_state_root;

    eth2::save_post_state_root(post_state_root)
}
