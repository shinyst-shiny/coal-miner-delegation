use num_enum::IntoPrimitive;
use thiserror::Error;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq, IntoPrimitive)]
#[repr(u32)]
pub enum CoalDelegationError {
    #[error("Stake delegation window is currently closed")]
    StakeWindowClosed,
}

impl From<CoalDelegationError> for solana_program::program_error::ProgramError {
    fn from(e: CoalDelegationError) -> Self {
        solana_program::program_error::ProgramError::Custom(e as u32)
    }
}

