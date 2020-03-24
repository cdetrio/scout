extern crate rustc_hex;
extern crate wasmi;
#[macro_use]
extern crate log;
extern crate env_logger;

use std::cmp::Ordering;

#[macro_use]
extern crate crunchy;

use primitive_types::U256;
use rustc_hex::{FromHex, ToHex};
use serde::{Deserialize, Serialize};
use std::env;
use std::fmt;
use wasmi::memory_units::Pages;
use wasmi::{
    Error as InterpreterError, Externals, FuncInstance, FuncRef, ImportsBuilder, MemoryInstance,
    MemoryRef, Module, ModuleImportResolver, ModuleInstance, NopExternals, RuntimeArgs,
    RuntimeValue, Signature, Trap, TrapKind, ValueType,
};

use byteorder::{BigEndian, LittleEndian, ByteOrder};

mod types;
use crate::types::*;

const LOADPRESTATEROOT_FUNC_INDEX: usize = 0;
const BLOCKDATASIZE_FUNC_INDEX: usize = 1;
const BLOCKDATACOPY_FUNC_INDEX: usize = 2;
const SAVEPOSTSTATEROOT_FUNC_INDEX: usize = 3;
const PUSHNEWDEPOSIT_FUNC_INDEX: usize = 4;
const USETICKS_FUNC_INDEX: usize = 5;
const DEBUG_PRINT32_FUNC: usize = 6;
const DEBUG_PRINT64_FUNC: usize = 7;
const DEBUG_PRINTMEM_FUNC: usize = 8;
const DEBUG_PRINTMEMHEX_FUNC: usize = 9;
const BIGNUM_ADD256_FUNC: usize = 10;
const BIGNUM_SUB256_FUNC: usize = 11;
const BIGNUM_MULMODMONT256_FUNC: usize = 12;
const BIGNUM_ADDMOD256_FUNC: usize = 13;
const BIGNUM_SUBMOD256_FUNC: usize = 14;


#[derive(Copy, Clone, PartialEq, Eq)]
struct BNU256(pub [u128; 2]);



impl Ord for BNU256 {
    #[inline]
    fn cmp(&self, other: &BNU256) -> Ordering {
        for (a, b) in self.0.iter().zip(other.0.iter()).rev() {
            if *a < *b {
                return Ordering::Less;
            } else if *a > *b {
                return Ordering::Greater;
            }
        }

        return Ordering::Equal;
    }
}

impl PartialOrd for BNU256 {
    #[inline]
    fn partial_cmp(&self, other: &BNU256) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl BNU256 {
    /// Initialize U256 from slice of bytes (big endian)
    pub fn from_slice(s: &[u8]) -> BNU256 {
        if s.len() != 32 {
            panic!("BNU256 from_slice error");
        }

        let mut n = [0; 2];
        //for (l, i) in (0..2).rev().zip((0..2).map(|i| i * 16)) {
        for (l, i) in (0..2).zip((0..2).map(|i| i * 16)) {
            n[l] = LittleEndian::read_u128(&s[i..]);
        }

        BNU256(n)
    }

}



struct Runtime<'a> {
    ticks_left: u32,
    memory: Option<MemoryRef>,
    pre_state: &'a Bytes32,
    block_data: &'a ShardBlockBody,
    post_state: Bytes32,
}

impl<'a> Runtime<'a> {
    fn new(
        pre_state: &'a Bytes32,
        block_data: &'a ShardBlockBody,
        memory: Option<MemoryRef>,
    ) -> Runtime<'a> {
        Runtime {
            ticks_left: 10_000_000, // FIXME: make this configurable
            memory: if memory.is_some() {
                memory
            } else {
                // Allocate a single page if no memory was exported.
                Some(MemoryInstance::alloc(Pages(1), Some(Pages(1))).unwrap())
            },
            pre_state: pre_state,
            block_data: block_data,
            post_state: Bytes32::default(),
        }
    }

    fn get_post_state(&self) -> Bytes32 {
        self.post_state
    }
}

impl<'a> Externals for Runtime<'a> {
    fn invoke_index(
        &mut self,
        index: usize,
        args: RuntimeArgs,
    ) -> Result<Option<RuntimeValue>, Trap> {
        match index {
            USETICKS_FUNC_INDEX => {
                let ticks: u32 = args.nth(0);
                if self.ticks_left < ticks {
                    // FIXME: use TrapKind::Host
                    return Err(Trap::new(TrapKind::Unreachable));
                }
                self.ticks_left -= ticks;
                Ok(None)
            }
            LOADPRESTATEROOT_FUNC_INDEX => {
                let ptr: u32 = args.nth(0);
                info!("loadprestateroot to {}", ptr);

                // TODO: add checks for out of bounds access
                let memory = self.memory.as_ref().expect("expects memory object");
                memory
                    .set(ptr, &self.pre_state.bytes)
                    .expect("expects writing to memory to succeed");

                Ok(None)
            }
            SAVEPOSTSTATEROOT_FUNC_INDEX => {
                let ptr: u32 = args.nth(0);
                info!("savepoststateroot from {}", ptr);

                // TODO: add checks for out of bounds access
                let memory = self.memory.as_ref().expect("expects memory object");
                memory
                    .get_into(ptr, &mut self.post_state.bytes)
                    .expect("expects reading from memory to succeed");

                Ok(None)
            }
            BLOCKDATASIZE_FUNC_INDEX => {
                let ret: i32 = self.block_data.data.len() as i32;
                info!("blockdatasize {}", ret);
                Ok(Some(ret.into()))
            }
            BLOCKDATACOPY_FUNC_INDEX => {
                let ptr: u32 = args.nth(0);
                let offset: u32 = args.nth(1);
                let length: u32 = args.nth(2);
                info!(
                    "blockdatacopy to {} from {} for {} bytes",
                    ptr, offset, length
                );

                // TODO: add overflow check
                let offset = offset as usize;
                let length = length as usize;

                // TODO: add checks for out of bounds access
                let memory = self.memory.as_ref().expect("expects memory object");
                memory
                    .set(ptr, &self.block_data.data[offset..length])
                    .expect("expects writing to memory to succeed");

                Ok(None)
            }
            PUSHNEWDEPOSIT_FUNC_INDEX => unimplemented!(),
            DEBUG_PRINT32_FUNC => {
                let value: u32 = args.nth(0);
                debug!("print.i32: {}", value);
                Ok(None)
            }
            DEBUG_PRINT64_FUNC => {
                let value: u64 = args.nth(0);
                debug!("print.i64: {}", value);
                Ok(None)
            }
            DEBUG_PRINTMEM_FUNC => {
                let ptr: u32 = args.nth(0);
                let length: u32 = args.nth(1);
                let mut buf = Vec::with_capacity(length as usize);
                unsafe { buf.set_len(length as usize) };
                // TODO: add checks for out of bounds access
                let memory = self.memory.as_ref().expect("expects memory object");
                memory
                    .get_into(ptr, &mut buf)
                    .expect("expects reading from memory to succeed");
                debug!("print: {}", String::from_utf8_lossy(&buf));
                Ok(None)
            }
            DEBUG_PRINTMEMHEX_FUNC => {
                let ptr: u32 = args.nth(0);
                let length: u32 = args.nth(1);
                let mut buf = Vec::with_capacity(length as usize);
                unsafe { buf.set_len(length as usize) };
                // TODO: add checks for out of bounds access
                let memory = self.memory.as_ref().expect("expects memory object");
                memory
                    .get_into(ptr, &mut buf)
                    .expect("expects reading from memory to succeed");
                debug!("print.hex: {}", buf.to_hex());
                Ok(None)
            }
            BIGNUM_ADD256_FUNC => {
                let a_ptr: u32 = args.nth(0);
                let b_ptr: u32 = args.nth(1);
                let c_ptr: u32 = args.nth(2);

                let mut a_raw = [0u8; 32];
                let mut b_raw = [0u8; 32];
                let mut c_raw = [0u8; 32];

                let memory = self.memory.as_ref().expect("expects memory object");
                memory
                    .get_into(a_ptr, &mut a_raw)
                    .expect("expects reading from memory to succeed");
                memory
                    .get_into(b_ptr, &mut b_raw)
                    .expect("expects reading from memory to succeed");

                let a = U256::from_big_endian(&a_raw);
                let b = U256::from_big_endian(&b_raw);
                let c = a.checked_add(b).expect("expects non-overflowing addition");
                c.to_big_endian(&mut c_raw);

                memory
                    .set(c_ptr, &c_raw)
                    .expect("expects writing to memory to succeed");

                Ok(None)
            }
            BIGNUM_SUB256_FUNC => {
                let a_ptr: u32 = args.nth(0);
                let b_ptr: u32 = args.nth(1);
                let c_ptr: u32 = args.nth(2);

                let mut a_raw = [0u8; 32];
                let mut b_raw = [0u8; 32];
                let mut c_raw = [0u8; 32];

                let memory = self.memory.as_ref().expect("expects memory object");
                memory
                    .get_into(a_ptr, &mut a_raw)
                    .expect("expects reading from memory to succeed");
                memory
                    .get_into(b_ptr, &mut b_raw)
                    .expect("expects reading from memory to succeed");

                let a = U256::from_big_endian(&a_raw);
                let b = U256::from_big_endian(&b_raw);
                let c = a
                    .checked_sub(b)
                    .expect("expects non-overflowing subtraction");
                c.to_big_endian(&mut c_raw);

                memory
                    .set(c_ptr, &c_raw)
                    .expect("expects writing to memory to succeed");

                Ok(None)
            }


            /* *** these bignum functions are used by https://github.com/cdetrio/rollup.rs/tree/benchreport-scout-bignums ***/

            // the code for mulmodmont256 was taken from https://github.com/zcash-hackworks/bn
            BIGNUM_MULMODMONT256_FUNC => {
                let a_ptr: u32 = args.nth(0);
                let b_ptr: u32 = args.nth(1);
                let mod_ptr: u32 = args.nth(2);
                let inv_ptr: u32 = args.nth(3);
                let ret_ptr: u32 = args.nth(4);
                // for the rollup.rs rust code, ret_ptr == a_ptr

                let mut a_raw = [0u8; 32];
                let mut b_raw = [0u8; 32];
                let mut mod_raw = [0u8; 32];
                let mut inv_raw = [0u8; 32];

                let memory = self.memory.as_ref().expect("expects memory object");
                memory
                    .get_into(a_ptr, &mut a_raw)
                    .expect("expects reading from memory to succeed");
                memory
                    .get_into(b_ptr, &mut b_raw)
                    .expect("expects reading from memory to succeed");
                memory
                    .get_into(mod_ptr, &mut mod_raw)
                    .expect("expects reading from memory to succeed");
                memory
                    .get_into(inv_ptr, &mut inv_raw)
                    .expect("expects reading from memory to succeed");


                //let mut a_u256 = U256::from_little_endian(&a_raw);
                let mut a = BNU256::from_slice(&a_raw);
                // a.0[1] are the hi (significant) bits
                // a.0[0] are the low (least significant) bits

                //let b_u256 = U256::from_little_endian(&b_raw);
                let b = BNU256::from_slice(&b_raw);
                //let modulus = U256::from_little_endian(&mod_raw);
                let modulus = BNU256::from_slice(&mod_raw);
                //let inv = U256::from_little_endian(&inv_raw);
                let inv = BNU256::from_slice(&inv_raw);

                mul_reduce(&mut a.0, &b.0, &modulus.0, inv.0[0]);

                if a >= modulus {
                    sub_noborrow(&mut a.0, &modulus.0);
                }

                let ret_lo = a.0[0].to_ne_bytes();
                let ret_hi = a.0[1].to_ne_bytes();
                let ret_raw = [&ret_lo[..], &ret_hi[..]].concat();

                let ret_from_slice = BNU256::from_slice(&ret_raw);

                memory
                    .set(ret_ptr, &ret_raw)
                    .expect("expects writing to memory to succeed");

                Ok(None)
            }
            BIGNUM_ADDMOD256_FUNC => {
                let a_ptr: u32 = args.nth(0);
                let b_ptr: u32 = args.nth(1);
                let mod_ptr: u32 = args.nth(2);
                let ret_ptr: u32 = args.nth(3);

                let mut a_raw = [0u8; 32];
                let mut b_raw = [0u8; 32];
                let mut mod_raw = [0u8; 32];
                let mut ret_raw = [0u8; 32];

                let memory = self.memory.as_ref().expect("expects memory object");
                memory
                    .get_into(a_ptr, &mut a_raw)
                    .expect("expects reading from memory to succeed");
                memory
                    .get_into(b_ptr, &mut b_raw)
                    .expect("expects reading from memory to succeed");
                memory
                    .get_into(mod_ptr, &mut mod_raw)
                    .expect("expects reading from memory to succeed");

                let a = U256::from_little_endian(&a_raw);
                let b = U256::from_little_endian(&b_raw);
                let modulus = U256::from_little_endian(&mod_raw);
                let mut ret = a.overflowing_add(b).0;

                if ret >= modulus {
                    ret = ret.checked_sub(modulus).expect("addmod256 expects non-overflowing subtraction");
                }

                ret.to_little_endian(&mut ret_raw);

                memory
                    .set(ret_ptr, &ret_raw)
                    .expect("expects writing to memory to succeed");

                Ok(None)
            }
            BIGNUM_SUBMOD256_FUNC => {
                let a_ptr: u32 = args.nth(0);
                let b_ptr: u32 = args.nth(1);
                let mod_ptr: u32 = args.nth(2);
                let ret_ptr: u32 = args.nth(3);

                let mut a_raw = [0u8; 32];
                let mut b_raw = [0u8; 32];
                let mut mod_raw = [0u8; 32];
                let mut ret_raw = [0u8; 32];

                let memory = self.memory.as_ref().expect("expects memory object");
                memory
                    .get_into(a_ptr, &mut a_raw)
                    .expect("expects reading from memory to succeed");
                memory
                    .get_into(b_ptr, &mut b_raw)
                    .expect("expects reading from memory to succeed");
                memory
                    .get_into(mod_ptr, &mut mod_raw)
                    .expect("expects reading from memory to succeed");

                let mut a = U256::from_little_endian(&a_raw);
                let b = U256::from_little_endian(&b_raw);
                let modulus = U256::from_little_endian(&mod_raw);

                //println!("BIGNUM_SUBMOD256_FUNC a: {:?}    b: {:?}", a, b);

                if a < b {
                    a = a.overflowing_add(modulus).0;
                }

                let ret = a.checked_sub(b).expect("submod256 expects non-overflowing subtraction");

                ret.to_little_endian(&mut ret_raw);

                memory
                    .set(ret_ptr, &ret_raw)
                    .expect("expects writing to memory to succeed");

                Ok(None)
            }
            _ => panic!("unknown function index"),
        }
    }
}




#[inline(always)]
fn split_u128(i: u128) -> (u128, u128) {
    (i >> 64, i & 0xFFFFFFFFFFFFFFFF)
}

#[inline(always)]
fn combine_u128(hi: u128, lo: u128) -> u128 {
    (hi << 64) | lo
}


#[inline]
fn sub_noborrow(a: &mut [u128; 2], b: &[u128; 2]) {
    #[inline]
    fn sbb(a: u128, b: u128, borrow: &mut u128) -> u128 {
        let (a1, a0) = split_u128(a);
        let (b1, b0) = split_u128(b);
        let (b, r0) = split_u128((1 << 64) + a0 - b0 - *borrow);
        let (b, r1) = split_u128((1 << 64) + a1 - b1 - ((b == 0) as u128));

        *borrow = (b == 0) as u128;

        combine_u128(r1, r0)
    }

    let mut borrow = 0;

    for (a, b) in a.into_iter().zip(b.iter()) {
        *a = sbb(*a, *b, &mut borrow);
    }

    debug_assert!(0 == borrow);
}


// TODO: Make `from_index` a const param
#[inline(always)]
fn mac_digit(from_index: usize, acc: &mut [u128; 4], b: &[u128; 2], c: u128) {
    #[inline]
    fn mac_with_carry(a: u128, b: u128, c: u128, carry: &mut u128) -> u128 {
        let (b_hi, b_lo) = split_u128(b);
        let (c_hi, c_lo) = split_u128(c);

        let (a_hi, a_lo) = split_u128(a);
        let (carry_hi, carry_lo) = split_u128(*carry);
        let (x_hi, x_lo) = split_u128(b_lo * c_lo + a_lo + carry_lo);
        let (y_hi, y_lo) = split_u128(b_lo * c_hi);
        let (z_hi, z_lo) = split_u128(b_hi * c_lo);
        // Brackets to allow better ILP
        let (r_hi, r_lo) = split_u128((x_hi + y_lo) + (z_lo + a_hi) + carry_hi);

        *carry = (b_hi * c_hi) + r_hi + y_hi + z_hi;

        combine_u128(r_lo, x_lo)
    }

    if c == 0 {
        return;
    }

    let mut carry = 0;

    debug_assert_eq!(acc.len(), 4);
    unroll! {
        for i in 0..2 {
            let a_index = i + from_index;
            acc[a_index] = mac_with_carry(acc[a_index], b[i], c, &mut carry);
        }
    }
    unroll! {
        for i in 0..2 {
            let a_index = i + from_index + 2;
            if a_index < 4 {
                let (a_hi, a_lo) = split_u128(acc[a_index]);
                let (carry_hi, carry_lo) = split_u128(carry);
                let (x_hi, x_lo) = split_u128(a_lo + carry_lo);
                let (r_hi, r_lo) = split_u128(x_hi + a_hi + carry_hi);

                carry = r_hi;

                acc[a_index] = combine_u128(r_lo, x_lo);
            }
        }
    }

    debug_assert!(carry == 0);
}

#[inline]
fn mul_reduce(this: &mut [u128; 2], by: &[u128; 2], modulus: &[u128; 2], inv: u128) {
//fn mul_reduce(this: &mut [u128; 2], by: &[u128; 2], modulus: &[u128; 2], inv: u128, debug: bool) {
    // The Montgomery reduction here is based on Algorithm 14.32 in
    // Handbook of Applied Cryptography
    // <http://cacr.uwaterloo.ca/hac/about/chap14.pdf>.

    let mut res = [0; 2 * 2];
    unroll! {
        for i in 0..2 {
            mac_digit(i, &mut res, by, this[i]);
        }
    }

    /*
    if debug {
        println!("mul_reduce res after first mac_digit: {:?}", res);
    }
    */


    unroll! {
        for i in 0..2 {
            let k = inv.wrapping_mul(res[i]);
            /*
            if debug {
                println!("i={:?}  k={:?}", i, k);
            }
            */
            mac_digit(i, &mut res, modulus, k);
        }
    }

    /*
    if debug {
        println!("mul_reduce res after inv.wrapping_mul: {:?}", res);
    }
    */


    this.copy_from_slice(&res[2..]);
}


struct RuntimeModuleImportResolver;

impl<'a> ModuleImportResolver for RuntimeModuleImportResolver {
    fn resolve_func(
        &self,
        field_name: &str,
        _signature: &Signature,
    ) -> Result<FuncRef, InterpreterError> {
        let func_ref = match field_name {
            "eth2_useTicks" => FuncInstance::alloc_host(
                Signature::new(&[ValueType::I32][..], None),
                USETICKS_FUNC_INDEX,
            ),
            "eth2_loadPreStateRoot" => FuncInstance::alloc_host(
                Signature::new(&[ValueType::I32][..], None),
                LOADPRESTATEROOT_FUNC_INDEX,
            ),
            "eth2_blockDataSize" => FuncInstance::alloc_host(
                Signature::new(&[][..], Some(ValueType::I32)),
                BLOCKDATASIZE_FUNC_INDEX,
            ),
            "eth2_blockDataCopy" => FuncInstance::alloc_host(
                Signature::new(&[ValueType::I32, ValueType::I32, ValueType::I32][..], None),
                BLOCKDATACOPY_FUNC_INDEX,
            ),
            "eth2_savePostStateRoot" => FuncInstance::alloc_host(
                Signature::new(&[ValueType::I32][..], None),
                SAVEPOSTSTATEROOT_FUNC_INDEX,
            ),
            "eth2_pushNewDeposit" => FuncInstance::alloc_host(
                Signature::new(&[ValueType::I32, ValueType::I32][..], None),
                PUSHNEWDEPOSIT_FUNC_INDEX,
            ),
            "debug_print32" => FuncInstance::alloc_host(
                Signature::new(&[ValueType::I32][..], None),
                DEBUG_PRINT32_FUNC,
            ),
            "debug_print64" => FuncInstance::alloc_host(
                Signature::new(&[ValueType::I64][..], None),
                DEBUG_PRINT64_FUNC,
            ),
            "debug_printMem" => FuncInstance::alloc_host(
                Signature::new(&[ValueType::I32, ValueType::I32][..], None),
                DEBUG_PRINTMEM_FUNC,
            ),
            "debug_printMemHex" => FuncInstance::alloc_host(
                Signature::new(&[ValueType::I32, ValueType::I32][..], None),
                DEBUG_PRINTMEMHEX_FUNC,
            ),
            "bignum_add256" => FuncInstance::alloc_host(
                Signature::new(&[ValueType::I32, ValueType::I32, ValueType::I32][..], None),
                BIGNUM_ADD256_FUNC,
            ),
            "bignum_sub256" => FuncInstance::alloc_host(
                Signature::new(&[ValueType::I32, ValueType::I32, ValueType::I32][..], None),
                BIGNUM_SUB256_FUNC,
            ),
            "mulmodmont256" => FuncInstance::alloc_host(
                Signature::new(&[ValueType::I32, ValueType::I32, ValueType::I32, ValueType::I32, ValueType::I32][..], None),
                BIGNUM_MULMODMONT256_FUNC,
            ),
            "addmod256" => FuncInstance::alloc_host(
                Signature::new(&[ValueType::I32, ValueType::I32, ValueType::I32, ValueType::I32][..], None),
                BIGNUM_ADDMOD256_FUNC,
            ),
            "submod256" => FuncInstance::alloc_host(
                Signature::new(&[ValueType::I32, ValueType::I32, ValueType::I32, ValueType::I32][..], None),
                BIGNUM_SUBMOD256_FUNC,
            ),
            _ => {
                return Err(InterpreterError::Function(format!(
                    "host module doesn't export function with name {}",
                    field_name
                )))
            }
        };
        Ok(func_ref)
    }
}

const BYTES_PER_SHARD_BLOCK_BODY: usize = 16384;
const ZERO_HASH: Bytes32 = Bytes32 { bytes: [0u8; 32] };

/// These are Phase 0 structures.
/// https://github.com/ethereum/eth2.0-specs/blob/dev/specs/core/0_beacon-chain.md
#[derive(Default, PartialEq, Clone, Debug)]
pub struct Deposit {}

/// These are Phase 2 Proposal 2 structures.

#[derive(Default, PartialEq, Clone, Debug)]
pub struct ExecutionScript {
    code: Vec<u8>,
}

#[derive(Default, PartialEq, Clone, Debug)]
pub struct BeaconState {
    execution_scripts: Vec<ExecutionScript>,
}

/// Shards are Phase 1 structures.
/// https://github.com/ethereum/eth2.0-specs/blob/dev/specs/core/1_shard-data-chains.md

#[derive(Default, PartialEq, Clone, Debug)]
pub struct ShardBlockHeader {}

#[derive(Default, PartialEq, Clone, Debug)]
pub struct ShardBlockBody {
    data: Vec<u8>,
}

#[derive(Default, PartialEq, Clone, Debug)]
pub struct ShardBlock {
    env: u64, // This is added by Phase 2 Proposal 2
    data: ShardBlockBody,
    // TODO: add missing fields
}

#[derive(Default, PartialEq, Clone, Debug)]
pub struct ShardState {
    exec_env_states: Vec<Bytes32>,
    slot: u64,
    parent_block: ShardBlockHeader,
    // TODO: add missing field
    // latest_state_roots: [bytes32, LATEST_STATE_ROOTS_LEMGTH]
}

impl fmt::Display for ShardBlockBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.data.to_hex())
    }
}

impl fmt::Display for ShardBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Shard block for environment {} with data {}",
            self.env, self.data
        )
    }
}

impl fmt::Display for ShardState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let states: Vec<String> = self
            .exec_env_states
            .iter()
            .map(|x| x.bytes.to_hex())
            .collect();
        write!(
            f,
            "Shard slot {} with environment states: {:?}",
            self.slot, states
        )
    }
}

pub fn execute_code(
    code: &[u8],
    pre_state: &Bytes32,
    block_data: &ShardBlockBody,
) -> (Bytes32, Vec<Deposit>) {
    debug!(
        "Executing codesize({}) and data: {}",
        code.len(),
        block_data
    );

    let module = Module::from_buffer(&code).expect("Module loading to succeed");
    let mut imports = ImportsBuilder::new();
    // FIXME: use eth2
    imports.push_resolver("env", &RuntimeModuleImportResolver);

    let instance = ModuleInstance::new(&module, &imports)
        .expect("Module instantation expected to succeed")
        .run_start(&mut NopExternals)
        .expect("Failed to run start function in module");

    let internal_mem = instance
        .export_by_name("memory")
        .expect("Module expected to have 'memory' export")
        .as_memory()
        .cloned()
        .expect("'memory' export should be a memory");

    let mut runtime = Runtime::new(pre_state, block_data, Some(internal_mem));

    let result = instance
        .invoke_export("main", &[], &mut runtime)
        .expect("Executed 'main'");

    info!("Result: {:?}", result);
    info!("Execution finished");

    (runtime.get_post_state(), vec![Deposit {}])
}

pub fn process_shard_block(
    state: &mut ShardState,
    beacon_state: &BeaconState,
    block: Option<ShardBlock>,
) {
    // println!("Beacon state: {:#?}", beacon_state);

    info!("Pre-execution: {}", state);

    // TODO: implement state root handling

    if let Some(block) = block {
        info!("Executing block: {}", block);

        // The execution environment identifier
        let env = block.env as usize; // FIXME: usize can be 32-bit
        let code = &beacon_state.execution_scripts[env].code;

        // Set post states to empty for any holes
        // for x in 0..env {
        //     state.exec_env_states.push(ZERO_HASH)
        // }
        let pre_state = &state.exec_env_states[env];
        let (post_state, deposits) = execute_code(code, pre_state, &block.data);
        state.exec_env_states[env] = post_state
    }

    // TODO: implement state + deposit root handling

    info!("Post-execution: {}", state)
}

fn load_file(filename: &str) -> Vec<u8> {
    std::fs::read(filename).expect(&format!("loading file {} failed", filename))
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct TestBeaconState {
    execution_scripts: Vec<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct TestShardBlock {
    env: u64,
    data: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct TestShardState {
    exec_env_states: Vec<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct TestFile {
    beacon_state: TestBeaconState,
    shard_blocks: Vec<TestShardBlock>,
    shard_pre_state: TestShardState,
    shard_post_state: TestShardState,
}

impl From<TestBeaconState> for BeaconState {
    fn from(input: TestBeaconState) -> Self {
        BeaconState {
            execution_scripts: input
                .execution_scripts
                .iter()
                .map(|x| ExecutionScript { code: load_file(x) })
                .collect(),
        }
    }
}

impl From<TestShardBlock> for ShardBlock {
    fn from(input: TestShardBlock) -> Self {
        ShardBlock {
            env: input.env,
            data: ShardBlockBody {
                data: input.data.from_hex().expect("invalid hex data"),
            },
        }
    }
}

impl From<TestShardState> for ShardState {
    fn from(input: TestShardState) -> Self {
        ShardState {
            exec_env_states: input
                .exec_env_states
                .iter()
                .map(|x| {
                    let state = x.from_hex().expect("invalid hex data");
                    assert!(state.len() == 32);
                    let mut ret = Bytes32::default();
                    ret.bytes.copy_from_slice(&state[..]);
                    ret
                })
                .collect(),
            slot: 0,
            parent_block: ShardBlockHeader {},
        }
    }
}

fn process_yaml_test(filename: &str) {
    info!("Processing {}...", filename);
    let content = load_file(&filename);
    let test_file: TestFile =
        serde_yaml::from_slice::<TestFile>(&content[..]).expect("expected valid yaml");
    debug!("{:#?}", test_file);

    let beacon_state: BeaconState = test_file.beacon_state.into();
    let pre_state: ShardState = test_file.shard_pre_state.into();
    let post_state: ShardState = test_file.shard_post_state.into();

    let mut shard_state = pre_state;
    for block in test_file.shard_blocks {
        process_shard_block(&mut shard_state, &beacon_state, Some(block.into()))
    }
    debug!("{}", shard_state);
    if shard_state != post_state {
        println!("Expected state: {}", post_state);
        println!("Got state: {}", shard_state);
        std::process::exit(1);
    } else {
        println!("Matching state.");
    }
}

fn main() {
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    process_yaml_test(if args.len() != 2 {
        "test.yaml"
    } else {
        &args[1]
    });
}
