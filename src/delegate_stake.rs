use coal_utils::spl::transfer;
use solana_program::{account_info::AccountInfo, program_error::ProgramError, clock::Clock, sysvar::Sysvar};

use crate::{
    error::CoalDelegationError, instruction::UndelegateStakeArgs, loaders::{load_delegated_stake, load_managed_proof}, state::ManagedProof, utils::AccountDeserialize
};

pub fn process_delegate_stake(
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> Result<(), ProgramError> {
    let [staker, miner, managed_proof_account_info, coal_proof_account_info, managed_proof_account_token_account_info, staker_token_account_info, delegated_stake_account_info, treasury, treasury_tokens, coal_program, token_program] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    let clock = Clock::get()?;

    let current_timestamp = clock.unix_timestamp;
    
    if let Some(secs_passed_hour) = current_timestamp.checked_rem(3600) {
        // passed 5 mins
        if secs_passed_hour > 300 {
            return Err(CoalDelegationError::StakeWindowClosed.into());
        }
    } else {
        return Err(ProgramError::ArithmeticOverflow);
    }

    // Parse args
    let args = UndelegateStakeArgs::try_from_bytes(instruction_data)?;
    let amount = u64::from_le_bytes(args.amount);

    if !staker.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    load_managed_proof(managed_proof_account_info, miner.key, false)?;
    load_delegated_stake(
        delegated_stake_account_info,
        staker.key,
        &managed_proof_account_info.key,
        true,
    )?;

    if *coal_program.key != coal_api::id() {
        return Err(ProgramError::IncorrectProgramId);
    }

    if *token_program.key != spl_token::id() {
        return Err(ProgramError::IncorrectProgramId);
    }

    let managed_proof = {
        let data = managed_proof_account_info.data.borrow();
        ManagedProof::try_from_bytes(&data)?.clone()
    };

    // transfer to miners token account
    transfer(
        staker,
        staker_token_account_info,
        managed_proof_account_token_account_info,
        token_program,
        amount,
    )?;

    // stake to coal program
    solana_program::program::invoke_signed(
        &coal_api::instruction::stake_coal(
            *managed_proof_account_info.key,
            *managed_proof_account_token_account_info.key,
            amount,
        ),
        &[
            managed_proof_account_info.clone(),
            coal_proof_account_info.clone(),
            managed_proof_account_token_account_info.clone(),
            treasury.clone(),
            treasury_tokens.clone(),
            coal_program.clone(),
            token_program.clone(),
        ],
        &[&[
            crate::consts::MANAGED_PROOF,
            miner.key.as_ref(),
            &[managed_proof.bump],
        ]],
    )?;

    // increase delegate stake balance
    if let Ok(mut data) = delegated_stake_account_info.data.try_borrow_mut() {
        let delegated_stake = crate::state::DelegatedStake::try_from_bytes_mut(&mut data)?;

        if let Some(new_total) = delegated_stake.amount.checked_add(amount) {
            delegated_stake.amount = new_total;
        } else {
            return Err(ProgramError::ArithmeticOverflow);
        }
    }
    Ok(())
}
