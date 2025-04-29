use color_eyre::eyre;

use crate::context::Context;

pub(crate) fn run(mut context: Context) -> eyre::Result<()> {
    let config = context.config()?;
    let ctx = context.secp_ctx();

    let pubkey = config.private_key.public_key(ctx);

    println!("{}", pubkey);

    Ok(())
}
