use std::sync::atomic::Ordering;

use stratum_apps::stratum_core::{
    bitcoin::{Amount, TxOut},
    channels_sv2::outputs::deserialize_outputs,
    handlers_sv2::HandleTemplateDistributionMessagesFromServerAsync,
    mining_sv2::SetNewPrevHash as SetNewPrevHashMp,
    parsers_sv2::{Mining, Tlv},
    template_distribution_sv2::*,
};
use tracing::{info, warn};

use crate::{
    channel_manager::{ChannelManager, RouteMessageTo},
    error::{self, PoolError, PoolErrorKind},
};

#[cfg_attr(not(test), hotpath::measure_all)]
impl HandleTemplateDistributionMessagesFromServerAsync for ChannelManager {
    type Error = PoolError<error::ChannelManager>;

    fn get_negotiated_extensions_with_server(
        &self,
        _server_id: Option<usize>,
    ) -> Result<Vec<u16>, Self::Error> {
        Ok(vec![])
    }

    async fn handle_new_template(
        &mut self,
        _server_id: Option<usize>,
        msg: NewTemplate<'_>,
        _tlv_fields: Option<&[Tlv]>,
    ) -> Result<(), Self::Error> {
        info!("Received: {}", msg);

        let messages = self.channel_manager_data.super_safe_lock(|channel_manager_data| {
            if msg.future_template {
                channel_manager_data.last_future_template = Some(msg.clone().into_static());
            }

            let mut messages: Vec<RouteMessageTo> = Vec::new();

            // External-TP / ghost-pool mode: when the Template Provider sets
            // `coinbase_tx_value_remaining == 0`, it is declaring that it has
            // already allocated the entire subsidy + fees into the outputs it
            // supplied in `template.coinbase_tx_outputs`. In that case we must
            // pass an empty `additional_coinbase_outputs` vector to
            // `on_new_template` so that the channels_sv2 sum check passes
            // (`sum([]) == 0 == value_remaining`) and the final coinbase
            // consists solely of the TP-provided outputs, which
            // `JobFactory::coinbase()` appends automatically after the (empty)
            // additional list.
            //
            // When `value_remaining > 0` we stay on the classic path: build a
            // single reward output whose value matches `value_remaining`, or
            // let the per-downstream `PayoutMode` split it as usual.
            let tp_owns_coinbase = msg.coinbase_tx_value_remaining == 0;
            if tp_owns_coinbase {
                tracing::debug!(
                    "Template: TP owns coinbase (value_remaining=0, template_outputs_count={})",
                    msg.coinbase_tx_outputs_count
                );
            }

            let coinbase_output: Vec<TxOut> = if tp_owns_coinbase {
                Vec::new()
            } else {
                let mut out = deserialize_outputs(channel_manager_data.coinbase_outputs.clone())
                    .expect("deserialization failed");
                out[0].value = Amount::from_sat(msg.coinbase_tx_value_remaining);
                out
            };

            for (downstream_id, downstream) in channel_manager_data.downstream.iter_mut() {
                // If REQUIRES_CUSTOM_WORK is set, skip template handling entirely (see https://github.com/stratum-mining/sv2-apps/issues/55)
                let requires_custom_work = downstream.requires_custom_work.load(Ordering::SeqCst);
                if requires_custom_work {
                    continue;
                }

                let messages_: Vec<RouteMessageTo<'_>> = downstream.downstream_data.super_safe_lock(|data| {
                    let downstream_coinbase_outputs = if tp_owns_coinbase {
                        Vec::new()
                    } else if let Some(ref payout_mode) = data.payout_mode {
                        payout_mode.coinbase_outputs(msg.coinbase_tx_value_remaining, &self.coinbase_reward_script)
                    } else {
                        coinbase_output.clone()
                    };

                    data.group_channel.on_new_template(msg.clone().into_static(), downstream_coinbase_outputs.clone()).map_err(|e| {
                        tracing::error!("Error while adding template to group channel");
                        PoolError::shutdown(e)
                    })?;

                    let group_channel_job = match msg.future_template {
                        true => {
                            let future_job_id = data.group_channel.get_future_job_id_from_template_id(msg.template_id).ok_or(
                                PoolError::shutdown(PoolErrorKind::JobNotFound)
                            )?;
                            data.group_channel.get_future_job(future_job_id).ok_or(
                                PoolError::shutdown(PoolErrorKind::JobNotFound)
                            )?
                        },
                        false => {
                            data.group_channel.get_active_job().ok_or(
                                PoolError::shutdown(PoolErrorKind::JobNotFound)
                            )?
                        },
                    };

                    let mut messages: Vec<RouteMessageTo> = vec![];

                    // if REQUIRES_STANDARD_JOBS is not set and the group channel is not empty
                    // we need to send the NewExtendedMiningJob message to the group channel
                    let requires_standard_jobs = downstream.requires_standard_jobs.load(Ordering::SeqCst);
                    let empty_group_channel = data.group_channel.get_channel_ids().is_empty();
                    if !requires_standard_jobs && !empty_group_channel {
                        messages.push((*downstream_id, Mining::NewExtendedMiningJob(group_channel_job.get_job_message().clone())).into());
                    }

                    // loop over every standard channel
                    // if REQUIRES_STANDARD_JOBS is not set, we need to call on_group_channel_job on each standard channel
                    // if REQUIRES_STANDARD_JOBS is set, we need to call on_new_template, and send individual NewMiningJob messages for each standard channel
                    for (channel_id, standard_channel) in data.standard_channels.iter_mut() {
                        if !requires_standard_jobs {
                            standard_channel.on_group_channel_job(group_channel_job.clone()).map_err(|e| {
                                tracing::error!("Error while adding group channel job to standard channel with id: {channel_id:?}");
                                PoolError::shutdown(e)
                            })?;
                        } else {
                            standard_channel.on_new_template(msg.clone().into_static(), downstream_coinbase_outputs.clone()).map_err(|e| {
                                tracing::error!("Error while adding template to standard channel");
                                PoolError::shutdown(e)
                            })?;

                            match msg.future_template {
                                true => {
                                    let standard_job_id = standard_channel.get_future_job_id_from_template_id(msg.template_id).expect("future job id must exist");
                                    let standard_job = standard_channel.get_future_job(standard_job_id).expect("future job must exist");
                                    messages.push((*downstream_id, Mining::NewMiningJob(standard_job.get_job_message().clone())).into());
                                },
                                false => {
                                    let standard_job = standard_channel.get_active_job().expect("active job must exist");
                                    messages.push((*downstream_id, Mining::NewMiningJob(standard_job.get_job_message().clone())).into());
                                },
                            }
                        }
                    }

                    // loop over every extended channel, and call on_group_channel_job on each extended channel
                    for (channel_id, extended_channel) in data.extended_channels.iter_mut() {
                        extended_channel.on_group_channel_job(group_channel_job.clone()).map_err(|e| {
                            tracing::error!("Error while adding group channel job to extended channel with id: {channel_id:?}");
                            PoolError::shutdown(e)
                        })?;
                    }

                    Ok::<Vec<RouteMessageTo<'_>>, Self::Error>(messages)
                })?;

                messages.extend(messages_);
            }
            Ok::<Vec<RouteMessageTo<'_>>, Self::Error>(messages)
        })?;

        for message in messages {
            // A send can only fail if the receiver side of the channel is closed.
            // Since this is an unbounded channel, it cannot fail due to capacity
            // limits (which would only apply to bounded channels).
            if let Err(e) = message.forward(&self.channel_manager_channel).await {
                tracing::error!("Failed to forward message {e:?}");
            }
        }

        Ok(())
    }

    async fn handle_request_tx_data_error(
        &mut self,
        _server_id: Option<usize>,
        msg: RequestTransactionDataError<'_>,
        _tlv_fields: Option<&[Tlv]>,
    ) -> Result<(), Self::Error> {
        warn!("Received: {}", msg);
        Ok(())
    }

    async fn handle_request_tx_data_success(
        &mut self,
        _server_id: Option<usize>,
        msg: RequestTransactionDataSuccess<'_>,
        _tlv_fields: Option<&[Tlv]>,
    ) -> Result<(), Self::Error> {
        info!("Received: {}", msg);
        Ok(())
    }

    async fn handle_set_new_prev_hash(
        &mut self,
        _server_id: Option<usize>,
        msg: SetNewPrevHash<'_>,
        _tlv_fields: Option<&[Tlv]>,
    ) -> Result<(), Self::Error> {
        info!("Received: {}", msg);

        let messages = self.channel_manager_data.super_safe_lock(|data| {
            data.last_new_prev_hash = Some(msg.clone().into_static());

            let mut messages: Vec<RouteMessageTo> = vec![];

            for (downstream_id, downstream) in data.downstream.iter_mut() {
                // If downstream requires custom work, skip template handling entirely (see https://github.com/stratum-mining/sv2-apps/issues/55)
                let requires_custom_work = downstream.requires_custom_work.load(Ordering::SeqCst);
                if requires_custom_work {
                    continue;
                }

                let downstream_messages = downstream.downstream_data.super_safe_lock(|data| {
                    let mut messages: Vec<RouteMessageTo> = vec![];

                    // call on_set_new_prev_hash on the group channel to update the channel state
                    data.group_channel.on_set_new_prev_hash(msg.clone().into_static()).map_err(|e| {
                        tracing::error!("Error while adding new prev hash to group channel");
                        PoolError::shutdown(e)
                    })?;

                    // did SetupConnection have the REQUIRES_STANDARD_JOBS flag set?
                    // if no, and the group channel is not empty, we need to send the SetNewPrevHashMp to the group channel
                    let requires_custom_work = downstream.requires_custom_work.load(Ordering::SeqCst);
                    let empty_group_channel = data.group_channel.get_channel_ids().is_empty();
                    if !requires_custom_work && !empty_group_channel {
                        let group_channel_id = data.group_channel.get_group_channel_id();
                        let activated_group_job_id = data.group_channel.get_active_job().expect("active job must exist").get_job_id();
                        let group_set_new_prev_hash_message = SetNewPrevHashMp {
                            channel_id: group_channel_id,
                            job_id: activated_group_job_id,
                            prev_hash: msg.prev_hash.clone(),
                            min_ntime: msg.header_timestamp,
                            nbits: msg.n_bits,
                        };

                        // send the SetNewPrevHash message to the group channel
                        messages.push((*downstream_id, Mining::SetNewPrevHash(group_set_new_prev_hash_message)).into());
                    }

                    // loop over every extended channel, and call on_set_new_prev_hash on each extended channel to update the channel state
                    for (channel_id, extended_channel) in data.extended_channels.iter_mut() {
                        extended_channel.on_set_new_prev_hash(msg.clone().into_static()).map_err(|e| {
                            tracing::error!("Error while adding new prev hash to extended channel: {channel_id:?} {e:?}");
                            PoolError::shutdown(e)
                        })?;
                    }

                    // loop over every standard channel, and call on_set_new_prev_hash on each standard channel to update the channel state
                    for (channel_id, standard_channel) in data.standard_channels.iter_mut() {
                        // call on_set_new_prev_hash on the standard channel to update the channel state
                        standard_channel.on_set_new_prev_hash(msg.clone().into_static()).map_err(|e| {
                            tracing::error!("Error while adding new prev hash to standard channel: {channel_id:?} {e:?}");
                            PoolError::shutdown(e)
                        })?;

                        // did SetupConnection have the REQUIRES_STANDARD_JOBS flag set?
                        // if yes, we need to send the SetNewPrevHashMp to each standard channel
                        if downstream.requires_standard_jobs.load(Ordering::SeqCst) {
                            let activated_standard_job_id = standard_channel.get_active_job().ok_or(
                                PoolError::shutdown(PoolErrorKind::JobNotFound)
                            )?.get_job_id();
                            let standard_set_new_prev_hash_message = SetNewPrevHashMp {
                                channel_id: *channel_id,
                                job_id: activated_standard_job_id,
                                prev_hash: msg.prev_hash.clone(),
                                min_ntime: msg.header_timestamp,
                                nbits: msg.n_bits,
                            };
                            messages.push((*downstream_id, Mining::SetNewPrevHash(standard_set_new_prev_hash_message)).into());
                        }
                    }

                    Ok::<Vec<RouteMessageTo<'_>>, Self::Error>(messages)
                })?;

                messages.extend(downstream_messages);
            }

            Ok::<Vec<RouteMessageTo<'_>>, Self::Error>(messages)
        })?;

        for message in messages {
            // A send can only fail if the receiver side of the channel is closed.
            // Since this is an unbounded channel, it cannot fail due to capacity
            // limits (which would only apply to bounded channels).
            if let Err(e) = message.forward(&self.channel_manager_channel).await {
                tracing::error!("Failed to forward message {e:?}");
            }
        }

        Ok(())
    }
}
