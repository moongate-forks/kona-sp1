//! Contains the [PrecompileOverride] trait implementation for the FPVM-accelerated precompiles.

use alloc::sync::Arc;
use kona_executor::PrecompileOverride;
use kona_mpt::{TrieDB, TrieDBFetcher, TrieDBHinter};
use revm::{
    handler::register::EvmHandler,
    precompile::{
        bn128, secp256k1, Precompile, PrecompileResult, PrecompileSpecId, PrecompileWithAddress,
    },
    primitives::Bytes,
    ContextPrecompiles, State,
};

pub const PRECOMPILE_HOOK_FD: u32 = 115;

/// Create an annotated precompile that simply tracks the cycle count of a precompile.
macro_rules! create_annotated_precompile {
    ($precompile:expr, $name:expr) => {
        PrecompileWithAddress(
            $precompile.0,
            Precompile::Standard(|input: &Bytes, gas_limit: u64| -> PrecompileResult {
                let precompile = $precompile.precompile();
                match precompile {
                    Precompile::Standard(precompile) => {
                        println!(concat!("cycle-tracker-report-start: precompile-", $name));
                        let result = precompile(input, gas_limit);
                        println!(concat!("cycle-tracker-report-end: precompile-", $name));
                        result
                    }
                    _ => panic!("Annotated precompile must be a standard precompile."),
                }
            }),
        )
    };
}

pub(crate) const ANNOTATED_BN_ADD: PrecompileWithAddress =
    create_annotated_precompile!(bn128::add::ISTANBUL, "bn-add");
pub(crate) const ANNOTATED_BN_MUL: PrecompileWithAddress =
    create_annotated_precompile!(bn128::mul::ISTANBUL, "bn-mul");
pub(crate) const ANNOTATED_BN_PAIR: PrecompileWithAddress =
    create_annotated_precompile!(bn128::pair::ISTANBUL, "bn-pair");
// pub(crate) const ANNOTATED_KZG_EVAL: PrecompileWithAddress = create_annotated_precompile!(
//     revm::precompile::kzg_point_evaluation::POINT_EVALUATION,
//     "kzg-eval"
// );
pub(crate) const ANNOTATED_EC_RECOVER: PrecompileWithAddress =
    create_annotated_precompile!(secp256k1::ECRECOVER, "ec-recover");

/// The [PrecompileOverride] implementation for the FPVM-accelerated precompiles.
#[derive(Debug)]
pub struct ZKVMPrecompileOverride<F, H>
where
    F: TrieDBFetcher,
    H: TrieDBHinter,
{
    _phantom: core::marker::PhantomData<(F, H)>,
}

impl<F, H> Default for ZKVMPrecompileOverride<F, H>
where
    F: TrieDBFetcher,
    H: TrieDBHinter,
{
    fn default() -> Self {
        Self {
            _phantom: core::marker::PhantomData::<(F, H)>,
        }
    }
}

impl<F, H> PrecompileOverride<F, H> for ZKVMPrecompileOverride<F, H>
where
    F: TrieDBFetcher,
    H: TrieDBHinter,
{
    fn set_precompiles(handler: &mut EvmHandler<'_, (), &mut State<&mut TrieDB<F, H>>>) {
        let spec_id = handler.cfg.spec_id;

        handler.pre_execution.load_precompiles = Arc::new(move || {
            let mut ctx_precompiles =
                ContextPrecompiles::new(PrecompileSpecId::from_spec_id(spec_id)).clone();

            // Extend with ZKVM-accelerated precompiles and annotated precompiles that track the cycle count.
            let override_precompiles = [
                ANNOTATED_BN_ADD,
                ANNOTATED_BN_MUL,
                ANNOTATED_BN_PAIR,
                // ANNOTATED_KZG_EVAL,
                ANNOTATED_EC_RECOVER,
            ];
            ctx_precompiles.extend(override_precompiles);

            ctx_precompiles
        });
    }
}
