use super::*;

impl SupervisorState {
    pub(super) async fn prepare_startup(
        &mut self,
        config: &mut Config,
        static_diagnostics: Vec<honk_config::diagnostic::DetailedDiagnostic>,
    ) -> DiagnosticBuckets {
        let mut startup_diagnostics = DiagnosticBuckets {
            static_diagnostics,
            providers: Vec::new(),
        };
        let mut requires_network = HashSet::new();
        for subscription in config.subscriptions.iter().filter(|s| s.enabled) {
            let Some(store) = self.store.as_ref() else {
                requires_network.insert(subscription.id);
                continue;
            };
            let mut diagnostics = Vec::new();
            match store
                .load_nodes_with_diagnostics(subscription, &mut diagnostics)
                .await
            {
                Ok(Some(nodes)) => {
                    honk_config::diagnostic::report_detailed_diagnostics(&diagnostics);
                    startup_diagnostics.replace_provider(subscription.id, diagnostics);
                    info!(
                        subscription = %subscription.name,
                        nodes = nodes.len(),
                        "Restored subscription"
                    );
                    config
                        .nodes
                        .retain(|node| node.subscription_id != Some(subscription.id));
                    config.nodes.extend(nodes);
                    self.observations
                        .write()
                        .get_mut(&subscription.id)
                        .unwrap()
                        .load = ProviderLoad {
                        updated_at: Some(SystemTime::now()),
                        cached: true,
                        error: None,
                        rejection: None,
                    };
                }
                Ok(None) => {
                    requires_network.insert(subscription.id);
                }
                Err(error) => {
                    honk_config::diagnostic::report_detailed_diagnostics(&diagnostics);
                    warn!(
                        subscription = %subscription.name,
                        %error,
                        "Failed to restore subscription"
                    );
                    requires_network.insert(subscription.id);
                    self.observations
                        .write()
                        .get_mut(&subscription.id)
                        .unwrap()
                        .load
                        .error = Some("cache_load_failed");
                }
            }
        }

        // Routing starts after this, so routed first fetches stay queued for
        // it and do not hold startup; direct ones get the grace period.
        let (direct, routed): (VecDeque<_>, VecDeque<_>) = std::mem::take(&mut self.pending)
            .into_iter()
            .partition(|id| {
                super::super::route::direct(&self.providers[id].authorized.subscription)
            });
        self.pending = direct;
        requires_network.retain(|id| !routed.contains(id));
        if !routed.is_empty() {
            info!(
                pending = routed.len(),
                "Subscriptions fetched through routing wait for it to start"
            );
        }
        let startup_limit = if config.experimental.native_api.enabled {
            MAX_ACTIVE_FETCHES
        } else {
            usize::MAX
        };
        let deadline = tokio::time::sleep(Duration::from_secs(5));
        tokio::pin!(deadline);
        let mut received = 0usize;
        loop {
            self.start_pending(startup_limit);
            if requires_network.is_empty() {
                break;
            }
            tokio::select! {
                result = self.fetches.join_next_with_id() => match result {
                    Some(Ok((task, completion))) => {
                        self.fetch_ids.remove(&task);
                        self.flights.remove(&completion.authorized.subscription.id);
                        received += 1;
                        let FetchCompletion {
                            authorized,
                            result,
                            diagnostics,
                        } = completion;
                        let subscription = authorized.subscription;
                        match result {
                            Some(Ok(nodes)) => {
                                startup_diagnostics
                                    .replace_provider(subscription.id, diagnostics);
                                info!(
                                    nodes = nodes.len(),
                                    "Subscription body accepted; startup publication pending"
                                );
                                config.nodes.retain(|node| {
                                    node.subscription_id != Some(subscription.id)
                                });
                                config.nodes.extend(nodes);
                                self.observations.write().get_mut(&subscription.id).unwrap().load = ProviderLoad { updated_at: Some(SystemTime::now()), cached: false, error: None, rejection: None };
                            }
                            Some(Err(error)) => {
                                self.observations.write().get_mut(&subscription.id).unwrap().load.error = Some(super::super::failure_code(&error));
                                warn!(subscription = %subscription.name, %error, "Failed to fetch subscription");
                            }
                            None => {}
                        }
                        requires_network.remove(&subscription.id);
                    }
                    Some(Err(error)) => {
                        if let Some(id) = self.fetch_ids.remove(&error.id()) {
                            self.flights.remove(&id);
                            requires_network.remove(&id);
                            self.observations.write().get_mut(&id).unwrap().load.error = Some("fetch_failed");
                        }
                        warn!(%error, "Subscription startup task failed");
                    }
                    None => break,
                },
                _ = &mut deadline => {
                    info!(
                        received,
                        total = self.providers.len(),
                        "Subscription fetch deadline reached; starting control plane"
                    );
                    break;
                }
            }
        }
        self.pending.extend(routed);
        if !self.fetches.is_empty() {
            info!(
                pending = self.fetches.len(),
                "Subscriptions still refreshing in background"
            );
        }
        startup_diagnostics
    }
}
