use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::{invoke, invoke_signed};
use anchor_lang::solana_program::pubkey::Pubkey as SolPubkey;
use anchor_spl::token_interface::TokenInterface;
use spl_token_2022::{extension::ExtensionType, instruction as token_instruction, state::Mint};

use crate::state::{RoleManager, StablecoinConfig};

/// Parameters for initializing a new stablecoin.
///
/// These determine which Token-2022 extensions get enabled on the mint.
/// Feature flags are **immutable** after initialization — choose carefully.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct InitializeParams {
    /// Human-readable name (max 32 chars)
    pub name: String,
    /// Ticker symbol (max 10 chars)
    pub symbol: String,
    /// Metadata URI (max 200 chars)
    pub uri: String,
    /// Token decimals (typically 6 for stablecoins)
    pub decimals: u8,
    /// SSS-2: Enable permanent delegate (allows seize)
    pub enable_permanent_delegate: bool,
    /// SSS-2: Enable transfer hook (for blacklist enforcement)
    pub enable_transfer_hook: bool,
    /// SSS-3: Enable confidential transfers (experimental)
    pub enable_confidential_transfers: bool,
    /// SSS-2: New token accounts start frozen by default
    pub default_account_frozen: bool,
    /// Address that can pause/unpause operations
    pub pauser: Pubkey,
    /// SSS-2: Address that manages the blacklist
    pub blacklister: Option<Pubkey>,
    /// SSS-2: Address that can seize tokens
    pub seizer: Option<Pubkey>,
    /// Optional hard supply cap. When set, mint_tokens will reject
    /// mints that would push total_minted above this ceiling.
    pub supply_cap: Option<u64>,
}

/// Accounts for the initialize instruction.
///
/// ## How it works:
/// 1. Creates the Token-2022 mint with the right extensions
/// 2. Initializes StablecoinConfig PDA (stores feature flags + metadata)
/// 3. Initializes RoleManager PDA (stores role assignments)
///
/// The config PDA becomes the mint authority AND freeze authority,
/// so only the program can mint/freeze — enforcing role-based access.
#[derive(Accounts)]
#[instruction(params: InitializeParams)]
pub struct Initialize<'info> {
    /// The authority creating this stablecoin (becomes master authority).
    #[account(mut)]
    pub authority: Signer<'info>,

    /// The stablecoin configuration PDA.
    /// Seeds: ["config", mint.key()] — one config per mint.
    #[account(
        init,
        payer = authority,
        space = StablecoinConfig::space(),
        seeds = [b"config", mint.key().as_ref()],
        bump,
    )]
    pub config: Account<'info, StablecoinConfig>,

    /// The role manager PDA.
    /// Seeds: ["roles", config.key()] — linked to the config.
    #[account(
        init,
        payer = authority,
        space = RoleManager::space(),
        seeds = [b"roles", config.key().as_ref()],
        bump,
    )]
    pub role_manager: Account<'info, RoleManager>,

    /// The Token-2022 mint account.
    /// Must be a fresh keypair — we create the mint in this instruction.
    /// CHECK: We validate and initialize this as a Token-2022 mint via CPI.
    #[account(mut)]
    pub mint: Signer<'info>,

    /// Token-2022 program (NOT the legacy token program).
    pub token_program: Interface<'info, TokenInterface>,

    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

/// Event emitted when a stablecoin is initialized.
#[event]
pub struct StablecoinInitialized {
    pub config: Pubkey,
    pub mint: Pubkey,
    pub authority: Pubkey,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub preset: String,
    pub enable_permanent_delegate: bool,
    pub enable_transfer_hook: bool,
    pub enable_confidential_transfers: bool,
    pub default_account_frozen: bool,
}

pub fn handler(ctx: Context<Initialize>, params: InitializeParams) -> Result<()> {
    require!(
        params.name.len() <= 32,
        crate::errors::SssError::NameTooLong
    );
    require!(
        params.symbol.len() <= 10,
        crate::errors::SssError::SymbolTooLong
    );
    require!(params.uri.len() <= 200, crate::errors::SssError::UriTooLong);

    // Extensions must be declared at mint creation time and are immutable.
    let mut extension_types: Vec<ExtensionType> = vec![
        ExtensionType::MetadataPointer,
        ExtensionType::MintCloseAuthority,
    ];

    if params.enable_permanent_delegate {
        extension_types.push(ExtensionType::PermanentDelegate);
    }

    if params.enable_transfer_hook {
        extension_types.push(ExtensionType::TransferHook);
    }

    if params.default_account_frozen {
        extension_types.push(ExtensionType::DefaultAccountState);
    }

    if params.enable_confidential_transfers {
        extension_types.push(ExtensionType::ConfidentialTransferMint);
    }

    let base_space = ExtensionType::try_calculate_account_len::<Mint>(&extension_types)
        .map_err(|_| crate::errors::SssError::InvalidDecimals)?;

    // Pre-fund for metadata TLV that token_metadata::initialize will realloc into.
    let metadata_space = 8
        + 4
        + 33
        + 32
        + (4 + params.name.len())
        + (4 + params.symbol.len())
        + (4 + params.uri.len())
        + 4;
    let space = base_space;
    let rent = &ctx.accounts.rent;
    let lamports = rent.minimum_balance(base_space + metadata_space);

    invoke(
        &anchor_lang::solana_program::system_instruction::create_account(
            ctx.accounts.authority.key,
            ctx.accounts.mint.key,
            lamports,
            space as u64,
            ctx.accounts.token_program.key,
        ),
        &[
            ctx.accounts.authority.to_account_info(),
            ctx.accounts.mint.to_account_info(),
            ctx.accounts.system_program.to_account_info(),
        ],
    )?;

    // Token-2022 requires extensions initialized BEFORE the mint itself.
    invoke(
        &spl_token_2022::extension::metadata_pointer::instruction::initialize(
            ctx.accounts.token_program.key,
            ctx.accounts.mint.key,
            Some(ctx.accounts.config.key()), // authority over metadata pointer
            Some(*ctx.accounts.mint.key),    // metadata address = the mint itself
        )?,
        &[ctx.accounts.mint.to_account_info()],
    )?;

    invoke(
        &token_instruction::initialize_mint_close_authority(
            ctx.accounts.token_program.key,
            ctx.accounts.mint.key,
            Some(&ctx.accounts.config.key()),
        )?,
        &[ctx.accounts.mint.to_account_info()],
    )?;

    // SSS-2: Config PDA as permanent delegate enables seize.
    if params.enable_permanent_delegate {
        invoke(
            &token_instruction::initialize_permanent_delegate(
                ctx.accounts.token_program.key,
                ctx.accounts.mint.key,
                &ctx.accounts.config.key(),
            )?,
            &[ctx.accounts.mint.to_account_info()],
        )?;
    }

    if params.default_account_frozen {
        invoke(
            &spl_token_2022::extension::default_account_state::instruction::initialize_default_account_state(
                ctx.accounts.token_program.key,
                ctx.accounts.mint.key,
                &spl_token_2022::state::AccountState::Frozen,
            )?,
            &[ctx.accounts.mint.to_account_info()],
        )?;
    }

    if params.enable_transfer_hook {
        let transfer_hook_program_id: SolPubkey = "8nWGGHT4kkuvtY8NqXeYEdiyC79qQ2taS82UGwmfdKgu"
            .parse()
            .unwrap();
        invoke(
            &spl_token_2022::extension::transfer_hook::instruction::initialize(
                ctx.accounts.token_program.key,
                ctx.accounts.mint.key,
                Some(ctx.accounts.config.key()),
                Some(transfer_hook_program_id),
            )?,
            &[ctx.accounts.mint.to_account_info()],
        )?;
    }

    // SSS-3: Auto-approve CT — no separate approval tx needed.
    if params.enable_confidential_transfers {
        invoke(
            &spl_token_2022::extension::confidential_transfer::instruction::initialize_mint(
                ctx.accounts.token_program.key,
                ctx.accounts.mint.key,
                Some(ctx.accounts.config.key()), // CT authority = config PDA
                true,                            // auto_approve_new_accounts
                None,                            // no auditor ElGamal pubkey
            )?,
            &[ctx.accounts.mint.to_account_info()],
        )?;
    }

    // Config PDA as both mint and freeze authority enforces role-based access.
    invoke(
        &token_instruction::initialize_mint2(
            ctx.accounts.token_program.key,
            ctx.accounts.mint.key,
            &ctx.accounts.config.key(), // mint authority = config PDA
            Some(&ctx.accounts.config.key()), // freeze authority = config PDA
            params.decimals,
        )?,
        &[ctx.accounts.mint.to_account_info()],
    )?;

    // Metadata stored directly on-chain via TokenMetadata extension (no Metaplex).
    invoke_signed(
        &spl_token_metadata_interface::instruction::initialize(
            ctx.accounts.token_program.key,
            ctx.accounts.mint.key,
            &ctx.accounts.config.key(), // update authority
            ctx.accounts.mint.key,      // metadata account = mint
            &ctx.accounts.config.key(), // mint authority (required signer)
            params.name.clone(),
            params.symbol.clone(),
            params.uri.clone(),
        ),
        &[
            ctx.accounts.mint.to_account_info(),
            ctx.accounts.config.to_account_info(),
        ],
        &[&[
            b"config",
            ctx.accounts.mint.key.as_ref(),
            &[ctx.bumps.config],
        ]],
    )?;

    let config = &mut ctx.accounts.config;
    config.authority = ctx.accounts.authority.key();
    config.mint = ctx.accounts.mint.key();
    config.name = params.name.clone();
    config.symbol = params.symbol.clone();
    config.uri = params.uri.clone();
    config.decimals = params.decimals;
    config.is_paused = false;
    config.total_minted = 0;
    config.total_burned = 0;
    config.enable_permanent_delegate = params.enable_permanent_delegate;
    config.enable_transfer_hook = params.enable_transfer_hook;
    config.enable_confidential_transfers = params.enable_confidential_transfers;
    config.default_account_frozen = params.default_account_frozen;
    config.supply_cap = params.supply_cap;
    config.bump = ctx.bumps.config;

    let role_manager = &mut ctx.accounts.role_manager;
    role_manager.config = config.key();
    role_manager.master_authority = ctx.accounts.authority.key();
    role_manager.pauser = params.pauser;
    role_manager.minters = Vec::new();
    role_manager.burners = vec![ctx.accounts.authority.key()];
    role_manager.blacklister = params.blacklister.unwrap_or(ctx.accounts.authority.key());
    role_manager.seizer = params.seizer.unwrap_or(ctx.accounts.authority.key());
    role_manager.bump = ctx.bumps.role_manager;

    let preset = if params.enable_confidential_transfers {
        "SSS-3"
    } else if params.enable_permanent_delegate && params.enable_transfer_hook {
        "SSS-2"
    } else {
        "SSS-1"
    };

    emit!(StablecoinInitialized {
        config: config.key(),
        mint: config.mint,
        authority: config.authority,
        name: config.name.clone(),
        symbol: config.symbol.clone(),
        decimals: config.decimals,
        preset: preset.to_string(),
        enable_permanent_delegate: config.enable_permanent_delegate,
        enable_transfer_hook: config.enable_transfer_hook,
        enable_confidential_transfers: config.enable_confidential_transfers,
        default_account_frozen: config.default_account_frozen,
    });

    msg!(
        "Initialized {} stablecoin: {} ({})",
        preset,
        config.name,
        config.symbol
    );

    Ok(())
}
