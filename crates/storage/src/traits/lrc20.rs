use crate::converters::lrc20::{
    convert_from_issue_announcement_model_to_announcement,
    convert_from_token_pubkey_announcement_model_to_announcement, create_issue_announcement_model,
    create_logo_announcement_model, create_proof_models, create_pubkey_freeze_announcement_model,
    create_token_pubkey_announcement_model, create_transfer_ownership_announcement_model,
    create_tx_freeze_announcement_model,
};
use crate::converters::lrc20::{create_lrc20_transaction_model, lrc20_transaction_from_model};

use crate::converters::spark::convert_model_to_spark_output;
use crate::entities::sea_orm_active_enums::{AnnouncementType, L1TxStatus, OperationType};

use crate::entities::{
    announcement, inner_key, issue_announcement, l1_transaction, lightning_commitment_proof,
    lightning_htlc_proof, multisig_proof, p2wsh_proof, proof, pubkey_freeze_announcement,
    spark_exit_proof, token, token_logo_announcement, token_pubkey_announcement,
    transfer_ownership_announcement, tx_freeze_announcement,
};
use bitcoin::hashes::Hash;

use crate::PgDatabaseConnectionManager;

#[cfg(feature = "bulletproof")]
use crate::entities::bulletproof;

use async_trait::async_trait;

use bitcoin::{ScriptBuf, Txid, secp256k1};
use lrc20_receipts::TokenPubkey;
use lrc20_types::announcements::{Announcement, TokenPubkeyInfo};
use lrc20_types::transactions::{Lrc20Transaction, Lrc20TxType};
use migration::OnConflict;
use sea_orm::*;

use sea_orm::DbErr;

#[derive(Debug)]
pub enum AnnouncementModel {
    TokenPubkey(token_pubkey_announcement::ActiveModel),
    TokenLogo(token_logo_announcement::ActiveModel),
    TxFreeze(tx_freeze_announcement::ActiveModel),
    PubkeyFreeze(pubkey_freeze_announcement::ActiveModel),
    Issue(issue_announcement::ActiveModel),
    TransferOwnership(transfer_ownership_announcement::ActiveModel),
}

#[derive(Debug)]
pub enum ReceiptProofModel {
    P2WSH(p2wsh_proof::ActiveModel),
    Multisig(multisig_proof::ActiveModel),
    LightningCommitment(lightning_commitment_proof::ActiveModel),
    LightningHtlc(lightning_htlc_proof::ActiveModel),
    SparkExit(spark_exit_proof::ActiveModel),
    #[cfg(feature = "bulletproof")]
    Bulletproof(bulletproof::ActiveModel),
}

#[async_trait]
pub trait Lrc20NodeStorage: PgDatabaseConnectionManager + Send + Sync + 'static {
    async fn get_lrc20_transaction_by_id(
        &self,
        txid: Txid,
    ) -> Result<Option<Lrc20Transaction>, DbErr> {
        let Some(lrc20_tx_model) = l1_transaction::Entity::find()
            .filter(l1_transaction::Column::Txid.eq(txid.to_byte_array().to_vec()))
            .one(&self.conn().await)
            .await?
        else {
            return Ok(None);
        };

        let tx_status = lrc20_tx_model.status.clone();
        let lrc20_tx = lrc20_transaction_from_model(lrc20_tx_model)
            .map_err(|e| DbErr::Custom(e.to_string()))?;

        // Protect the resulting transaction by returning an issue announcement insetead of an
        // issue transaction if status is [`TxStatus::InvalidIssue`].
        let protected_lrc20_tx = match (&lrc20_tx.tx_type, tx_status) {
            (Lrc20TxType::Issue { announcement, .. }, L1TxStatus::InvalidIssue) => {
                Lrc20Transaction::new(
                    lrc20_tx.bitcoin_tx,
                    Lrc20TxType::Announcement(announcement.clone().into()),
                )
            }
            _ => lrc20_tx,
        };

        Ok(Some(protected_lrc20_tx))
    }

    async fn get_lrc_20_transactions(
        &self,
        page_size: u64,
        page_number: u64,
    ) -> Result<Vec<Lrc20Transaction>, DbErr> {
        let conn = self.conn().await;
        let paginator = l1_transaction::Entity::find()
            .order_by_asc(l1_transaction::Column::Timestamp)
            .paginate(&conn, page_size);

        let page_txs = paginator.fetch_page(page_number).await?;

        page_txs
            .into_iter()
            .map(|tx_model| {
                lrc20_transaction_from_model(tx_model)
                    .map_err(|e| DbErr::Custom(format!("Failed to deserialize LRC20 tx: {}", e)))
            })
            .collect()
    }

    async fn get_lrc_20_transactions_by_ids(
        &self,
        txids: Vec<Txid>,
    ) -> Result<Vec<Lrc20Transaction>, DbErr> {
        let txids = txids
            .iter()
            .map(|txid| txid.to_byte_array().to_vec())
            .collect::<Vec<_>>();
        let txs = l1_transaction::Entity::find()
            .filter(l1_transaction::Column::Txid.is_in(txids))
            .all(&self.conn().await)
            .await?;

        txs.into_iter()
            .map(|tx_model| {
                lrc20_transaction_from_model(tx_model)
                    .map_err(|e| DbErr::Custom(format!("Failed to deserialize LRC20 tx: {}", e)))
            })
            .collect()
    }

    async fn delete_list_lrc20_transactions(
        &self,
        txids: Vec<Txid>,
    ) -> Result<DeleteResult, DbErr> {
        l1_transaction::Entity::delete_many()
            .filter(
                l1_transaction::Column::Txid.is_in(
                    txids
                        .iter()
                        .map(|txid| txid.to_byte_array().to_vec())
                        .collect::<Vec<_>>(),
                ),
            )
            .exec(&self.conn().await)
            .await
    }

    async fn delete_lrc20_transaction(&self, txid: Txid) -> Result<DeleteResult, DbErr> {
        let tx = l1_transaction::Entity::find()
            .filter(l1_transaction::Column::Txid.eq(txid.to_byte_array().to_vec()))
            .one(&self.conn().await)
            .await?;

        if let Some(tx) = tx {
            tx.delete(&self.conn().await).await
        } else {
            Ok(DeleteResult { rows_affected: 0 })
        }
    }

    // TODO: decompose it
    async fn insert_lrc20_transaction(&self, tx: Lrc20Transaction) -> Result<(), DbErr> {
        let bitcoin_tx = tx.bitcoin_tx.clone();
        let txid = bitcoin_tx.txid().to_byte_array().to_vec();

        let mut proof_models = Vec::new();

        let txn = self.tx().await?;

        let lrc20_tx_model = create_lrc20_transaction_model(&tx, L1TxStatus::Handling);

        l1_transaction::Entity::insert(lrc20_tx_model)
            .on_conflict(
                OnConflict::column(l1_transaction::Column::Txid)
                    .update_columns([
                        l1_transaction::Column::RawTx,
                        l1_transaction::Column::Status,
                    ])
                    .to_owned(),
            )
            .exec(&txn)
            .await?;

        let mut announcement_model = None;
        let mut announcement_token_pubkey = None;
        let mut announcement_type = None;

        match &tx.tx_type {
            Lrc20TxType::Transfer {
                input_proofs,
                output_proofs,
            } => {
                proof_models = create_proof_models(&bitcoin_tx, output_proofs.clone());

                for i in input_proofs.keys() {
                    let Some(vin) = bitcoin_tx.input.get(*i as usize) else {
                        continue;
                    };

                    let proof = proof::Entity::find()
                        .filter(
                            proof::Column::Txid.eq(vin
                                .previous_output
                                .txid
                                .to_byte_array()
                                .to_vec()),
                        )
                        .filter(proof::Column::Vout.eq(vin.previous_output.vout as i32))
                        .one(&self.conn().await)
                        .await?;

                    if let Some(proof) = proof {
                        let mut proof_model: proof::ActiveModel = proof.into();
                        proof_model.spend_txid =
                            Set(Some(bitcoin_tx.txid().to_byte_array().to_vec()));
                        proof_model.spend_vout = Set(Some(*i as i32));
                        proof_model.update(&txn).await?;
                    }
                }
            }
            Lrc20TxType::Issue {
                output_proofs,
                announcement,
            } => {
                if let Some(proofs) = output_proofs {
                    if let Some(first_proof) = proofs.values().next() {
                        announcement_token_pubkey = Some(first_proof.receipt().token_pubkey);
                    }
                    proof_models = create_proof_models(&bitcoin_tx, proofs.clone());
                }
                announcement_type = Some(AnnouncementType::Issue);
                announcement_model = Some(AnnouncementModel::Issue(
                    create_issue_announcement_model(txid.clone(), announcement.clone()),
                ));
            }
            Lrc20TxType::SparkExit { output_proofs } => {
                proof_models = create_proof_models(&bitcoin_tx, output_proofs.clone());
            }
            Lrc20TxType::Announcement(announcement) => {
                announcement_token_pubkey = Some(announcement.token_pubkey());
                match announcement {
                    Announcement::TokenPubkey(token_pubkey_announcement) => {
                        announcement_type = Some(AnnouncementType::TokenPubkey);
                        announcement_model = Some(AnnouncementModel::TokenPubkey(
                            create_token_pubkey_announcement_model(
                                txid.clone(),
                                token_pubkey_announcement.clone(),
                            ),
                        ));
                    }
                    Announcement::TxFreeze(tx_freeze_announcement) => {
                        announcement_type = Some(AnnouncementType::TxFreeze);
                        announcement_model = Some(AnnouncementModel::TxFreeze(
                            create_tx_freeze_announcement_model(
                                txid.clone(),
                                tx_freeze_announcement
                                    .outpoint
                                    .txid
                                    .to_byte_array()
                                    .to_vec(),
                                tx_freeze_announcement.outpoint.vout,
                            ),
                        ));
                    }
                    Announcement::PubkeyFreeze(pubkey_freeze_announcement) => {
                        announcement_type = Some(AnnouncementType::PubkeyFreeze);
                        announcement_model = Some(AnnouncementModel::PubkeyFreeze(
                            create_pubkey_freeze_announcement_model(
                                txid.clone(),
                                pubkey_freeze_announcement.pubkey.into(),
                            ),
                        ));
                    }
                    Announcement::TransferOwnership(transfer_ownership_announcement) => {
                        announcement_type = Some(AnnouncementType::TransferOwnership);
                        announcement_model = Some(AnnouncementModel::TransferOwnership(
                            create_transfer_ownership_announcement_model(
                                txid.clone(),
                                transfer_ownership_announcement.new_owner.clone(),
                            ),
                        ));
                    }
                    Announcement::Issue(issue_announcement) => {
                        announcement_type = Some(AnnouncementType::Issue);
                        announcement_model =
                            Some(AnnouncementModel::Issue(create_issue_announcement_model(
                                txid.clone(),
                                issue_announcement.clone(),
                            )));
                    }
                    Announcement::TokenLogo(logo_announcement) => {
                        announcement_type = Some(AnnouncementType::TokenLogo);
                        announcement_model = Some(AnnouncementModel::TokenLogo(
                            create_logo_announcement_model(txid.clone(), logo_announcement.clone()),
                        ));
                    }
                }
            }
        }

        for (proof, inner_keys, tokens, proof_model) in proof_models {
            proof::Entity::insert(proof)
                .on_conflict(
                    OnConflict::columns([proof::Column::Txid, proof::Column::Vout])
                        .update_columns([
                            proof::Column::SpendTxid,
                            proof::Column::SpendVout,
                            proof::Column::IsFrozen,
                            proof::Column::Script,
                            proof::Column::ScriptType,
                            proof::Column::Metadata,
                            proof::Column::ProofType,
                        ])
                        .to_owned(),
                )
                .exec(&txn)
                .await?;

            for inner_key in inner_keys {
                inner_key::Entity::insert(inner_key)
                    .on_conflict(
                        OnConflict::columns([inner_key::Column::Txid, inner_key::Column::Vout])
                            .update_column(inner_key::Column::Pubkey)
                            .to_owned(),
                    )
                    .exec(&txn)
                    .await?;
            }

            for token in tokens {
                token::Entity::insert(token)
                    .on_conflict(
                        OnConflict::columns([token::Column::Txid, token::Column::Vout])
                            .update_columns([
                                token::Column::TokenAmount,
                                token::Column::TokenPubkey,
                            ])
                            .to_owned(),
                    )
                    .exec(&txn)
                    .await?;
            }

            if let Some(proof_model) = proof_model {
                self.insert_proof_model(proof_model, &txn).await?;
            }
        }

        if let (Some(announcement_type), Some(token_pubkey)) =
            (announcement_type, announcement_token_pubkey)
        {
            let announcement = announcement::ActiveModel {
                txid: Set(txid.clone()),
                token_pubkey: Set(token_pubkey.to_bytes().to_vec()),
                r#type: Set(announcement_type),
                ..Default::default()
            };

            announcement::Entity::insert(announcement)
                .on_conflict(
                    OnConflict::columns([announcement::Column::Txid])
                        .update_columns([
                            announcement::Column::TokenPubkey,
                            announcement::Column::Type,
                        ])
                        .to_owned(),
                )
                .exec(&txn)
                .await?;
        }

        if let Some(model) = announcement_model {
            self.insert_announcement_model(model, &txn).await?;
        }

        txn.commit().await?;

        Ok(())
    }

    async fn insert_proof_model(
        &self,
        proof: ReceiptProofModel,
        txn: &DatabaseTransaction,
    ) -> Result<(), DbErr> {
        match proof {
            ReceiptProofModel::P2WSH(active_model) => {
                p2wsh_proof::Entity::insert(active_model)
                    .on_conflict(
                        OnConflict::columns([p2wsh_proof::Column::Txid, p2wsh_proof::Column::Vout])
                            .update_column(p2wsh_proof::Column::Script)
                            .to_owned(),
                    )
                    .exec(txn)
                    .await?;
            }
            ReceiptProofModel::Multisig(active_model) => {
                multisig_proof::Entity::insert(active_model)
                    .on_conflict(
                        OnConflict::columns([
                            multisig_proof::Column::Txid,
                            multisig_proof::Column::Vout,
                        ])
                        .update_column(multisig_proof::Column::M)
                        .to_owned(),
                    )
                    .exec(txn)
                    .await?;
            }
            ReceiptProofModel::LightningCommitment(active_model) => {
                lightning_commitment_proof::Entity::insert(active_model)
                    .on_conflict(
                        OnConflict::columns([
                            lightning_commitment_proof::Column::Txid,
                            lightning_commitment_proof::Column::Vout,
                        ])
                        .update_columns([
                            lightning_commitment_proof::Column::LocalDelayedPubkey,
                            lightning_commitment_proof::Column::ToSelfDelay,
                            lightning_commitment_proof::Column::RevocationPubkey,
                        ])
                        .to_owned(),
                    )
                    .exec(txn)
                    .await?;
            }
            ReceiptProofModel::LightningHtlc(active_model) => {
                lightning_htlc_proof::Entity::insert(active_model)
                    .on_conflict(
                        OnConflict::columns([
                            lightning_htlc_proof::Column::Txid,
                            lightning_htlc_proof::Column::Vout,
                        ])
                        .update_columns([
                            lightning_htlc_proof::Column::LocalHtlcKey,
                            lightning_htlc_proof::Column::RemoteHtlcKey,
                            lightning_htlc_proof::Column::PaymentHash,
                            lightning_htlc_proof::Column::RevocationKeyHash,
                            lightning_htlc_proof::Column::CltvExpiry,
                        ])
                        .to_owned(),
                    )
                    .exec(txn)
                    .await?;
            }
            #[cfg(feature = "bulletproof")]
            ReceiptProofModel::Bulletproof(active_model) => {
                bulletproof::Entity::insert(active_model)
                    .on_conflict(
                        OnConflict::columns([bulletproof::Column::Txid, bulletproof::Column::Vout])
                            .update_columns([
                                bulletproof::Column::SenderKey,
                                bulletproof::Column::Commitment,
                                bulletproof::Column::Proof,
                                bulletproof::Column::Signature,
                                bulletproof::Column::TokenPubkeySignature,
                            ])
                            .to_owned(),
                    )
                    .exec(txn)
                    .await?;
            }
            ReceiptProofModel::SparkExit(active_model) => {
                spark_exit_proof::Entity::insert(active_model)
                    .on_conflict(
                        OnConflict::columns([
                            spark_exit_proof::Column::Txid,
                            spark_exit_proof::Column::Vout,
                        ])
                        .update_columns([
                            spark_exit_proof::Column::RevocationKey,
                            spark_exit_proof::Column::DelayKey,
                            spark_exit_proof::Column::Locktime,
                        ])
                        .to_owned(),
                    )
                    .exec(txn)
                    .await?;
            }
        }

        Ok(())
    }

    async fn insert_announcement_model(
        &self,
        announcement: AnnouncementModel,
        txn: &DatabaseTransaction,
    ) -> Result<(), DbErr> {
        match announcement {
            AnnouncementModel::TokenPubkey(model) => {
                token_pubkey_announcement::Entity::insert(model)
                    .on_conflict(
                        OnConflict::columns([token_pubkey_announcement::Column::Txid])
                            .update_columns([
                                token_pubkey_announcement::Column::Name,
                                token_pubkey_announcement::Column::Symbol,
                                token_pubkey_announcement::Column::Decimal,
                                token_pubkey_announcement::Column::MaxSupply,
                                token_pubkey_announcement::Column::IsFreezable,
                            ])
                            .to_owned(),
                    )
                    .exec(txn)
                    .await?;
            }
            AnnouncementModel::TxFreeze(model) => {
                tx_freeze_announcement::Entity::insert(model)
                    .on_conflict(
                        OnConflict::columns([tx_freeze_announcement::Column::Txid])
                            .update_columns([
                                tx_freeze_announcement::Column::FreezeTxid,
                                tx_freeze_announcement::Column::FreezeVout,
                            ])
                            .to_owned(),
                    )
                    .exec(txn)
                    .await?;
            }
            AnnouncementModel::PubkeyFreeze(model) => {
                pubkey_freeze_announcement::Entity::insert(model)
                    .on_conflict(
                        OnConflict::columns([pubkey_freeze_announcement::Column::Txid])
                            .update_column(pubkey_freeze_announcement::Column::FreezePubkey)
                            .to_owned(),
                    )
                    .exec(txn)
                    .await?;
            }
            AnnouncementModel::Issue(model) => {
                issue_announcement::Entity::insert(model)
                    .on_conflict(
                        OnConflict::columns([issue_announcement::Column::Txid])
                            .update_column(issue_announcement::Column::Amount)
                            .to_owned(),
                    )
                    .exec(txn)
                    .await?;
            }
            AnnouncementModel::TransferOwnership(model) => {
                transfer_ownership_announcement::Entity::insert(model)
                    .on_conflict(
                        OnConflict::columns([transfer_ownership_announcement::Column::Txid])
                            .update_column(transfer_ownership_announcement::Column::NewOwner)
                            .to_owned(),
                    )
                    .exec(txn)
                    .await?;
            }
            AnnouncementModel::TokenLogo(model) => {
                token_logo_announcement::Entity::insert(model)
                    .on_conflict(
                        OnConflict::columns([token_logo_announcement::Column::Txid])
                            .update_column(token_logo_announcement::Column::LogoUrl)
                            .to_owned(),
                    )
                    .exec(txn)
                    .await?;
            }
        };

        Ok(())
    }

    async fn set_lrc20_tx_status(&self, txid: Txid, tx_status: L1TxStatus) -> Result<(), DbErr> {
        let conn = self.conn().await;
        let tx = l1_transaction::Entity::find()
            .filter(l1_transaction::Column::Txid.eq(txid.to_byte_array().to_vec()))
            .one(&conn)
            .await?;

        if let Some(tx) = tx {
            let mut tx_active_model: l1_transaction::ActiveModel = tx.into();
            tx_active_model.status = Set(tx_status);
            tx_active_model.update(&conn).await?;
        }

        Ok(())
    }

    async fn is_proof_spent(&self, txid: Txid, vout: i32) -> Result<bool, DbErr> {
        let proof = proof::Entity::find()
            .filter(proof::Column::Txid.eq(txid.to_byte_array().to_vec()))
            .filter(proof::Column::Vout.eq(vout))
            .filter(proof::Column::SpendTxid.is_not_null())
            .one(&self.conn().await)
            .await?;

        Ok(proof.is_some())
    }

    async fn toggle_proof_freeze(&self, txid: Txid, vout: u32) -> Result<(), DbErr> {
        let conn = self.conn().await;
        let proof = proof::Entity::find()
            .filter(proof::Column::Txid.eq(txid.to_byte_array().to_vec()))
            .filter(proof::Column::Vout.eq(vout as i32))
            .one(&conn)
            .await?;

        if let Some(proof) = proof {
            let is_frozen = proof.is_frozen;
            let mut proof_model: proof::ActiveModel = proof.into();
            proof_model.is_frozen = Set(!is_frozen);
            proof_model.update(&conn).await?;
        }

        Ok(())
    }

    async fn is_proof_frozen(&self, txid: Txid, vout: u32) -> Result<bool, DbErr> {
        let proof = proof::Entity::find()
            .filter(proof::Column::Txid.eq(txid.to_byte_array().to_vec()))
            .filter(proof::Column::Vout.eq(vout as i32))
            .one(&self.conn().await)
            .await?;

        Ok(proof.map(|proof| proof.is_frozen).unwrap_or_default())
    }

    async fn is_pubkey_frozen(
        &self,
        pubkey: secp256k1::PublicKey,
        token_pubkey: secp256k1::PublicKey,
    ) -> Result<bool, DbErr> {
        let freezes = pubkey_freeze_announcement::Entity::find()
            .inner_join(announcement::Entity)
            .filter(
                pubkey_freeze_announcement::Column::FreezePubkey.eq(pubkey.serialize().to_vec()),
            )
            .filter(announcement::Column::TokenPubkey.eq(token_pubkey.serialize().to_vec()))
            .all(&self.conn().await)
            .await?;

        Ok(freezes.len() % 2 == 1)
    }

    async fn get_token_pubkey_info(
        &self,
        token_pubkey: TokenPubkey,
    ) -> Result<Option<TokenPubkeyInfo>, DbErr> {
        let conn = self.conn().await;
        let token_pubkey_bytes = token_pubkey.to_bytes().to_vec();

        let Some(announcement) = announcement::Entity::find()
            .inner_join(l1_transaction::Entity)
            .filter(l1_transaction::Column::Status.eq(L1TxStatus::Attached))
            .filter(announcement::Column::TokenPubkey.eq(token_pubkey_bytes.clone()))
            .filter(announcement::Column::Type.eq(AnnouncementType::TokenPubkey))
            .one(&conn)
            .await?
        else {
            return Ok(None);
        };

        let Some(token_pubkey_announcement) = announcement
            .find_related(token_pubkey_announcement::Entity)
            .one(&conn)
            .await?
        else {
            return Ok(None);
        };

        let token_pubkey_announcement =
            convert_from_token_pubkey_announcement_model_to_announcement(
                &token_pubkey_announcement,
                &announcement,
            );

        let issue_announcements = announcement::Entity::find()
            .filter(announcement::Column::TokenPubkey.eq(token_pubkey_bytes.clone()))
            .filter(announcement::Column::Type.eq(AnnouncementType::Issue))
            .all(&conn)
            .await?;

        let mut total_supply = 0u128;

        for issue_announcement in issue_announcements {
            let Some(related_issue_data) = issue_announcement
                .find_related(issue_announcement::Entity)
                .one(&conn)
                .await?
            else {
                continue;
            };

            let parsed_issue_announcement = convert_from_issue_announcement_model_to_announcement(
                &related_issue_data,
                &issue_announcement,
            );

            total_supply = total_supply.saturating_add(parsed_issue_announcement.amount);
        }

        let mut token_pubkey_info = TokenPubkeyInfo {
            announcement: Some(token_pubkey_announcement),
            total_supply,
            owner: None,
            logo_url: None,
        };

        let transfer_ownership_announcement = announcement::Entity::find()
            .filter(announcement::Column::TokenPubkey.eq(token_pubkey_bytes.clone()))
            .filter(announcement::Column::Type.eq(AnnouncementType::TransferOwnership))
            .join(
                JoinType::InnerJoin,
                announcement::Relation::L1Transaction.def(),
            )
            .order_by_desc(l1_transaction::Column::Timestamp)
            .one(&conn)
            .await?;

        if let Some(announcement) = &transfer_ownership_announcement {
            let transfer_ownership = announcement
                .find_related(transfer_ownership_announcement::Entity)
                .one(&conn)
                .await?;

            if let Some(transfer_ownership) = transfer_ownership {
                token_pubkey_info.owner = Some(ScriptBuf::from_bytes(transfer_ownership.new_owner));
            }
        }

        let logo_announcement = announcement::Entity::find()
            .filter(announcement::Column::TokenPubkey.eq(token_pubkey_bytes.clone()))
            .filter(announcement::Column::Type.eq(AnnouncementType::TokenLogo))
            .join(
                JoinType::InnerJoin,
                announcement::Relation::L1Transaction.def(),
            )
            .order_by_desc(l1_transaction::Column::Timestamp)
            .one(&conn)
            .await?;

        if let Some(announcement) = &logo_announcement {
            let logo = announcement
                .find_related(token_logo_announcement::Entity)
                .one(&conn)
                .await?;

            if let Some(logo) = logo {
                token_pubkey_info.logo_url = Some(logo.logo_url);
            }
        }

        Ok(Some(token_pubkey_info))
    }
}
