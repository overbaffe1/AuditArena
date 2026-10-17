# Публичные upstream-фрагменты, использованные в раунде 21

Источник: `e2b-dev/runtime` commit `4f35ab01d346408b29b843eac98fdea61a21f8d1` (main; API GitHub сообщил commit date 2026-10-17T10:50:07Z). SHA-256 закреплённого codeload tarball: `8390ccdebafa310e27843c779ecc2293fcea4fd02924d1d918f647d057224eb4`. Файлы token generator, `envd_reinit.go`, `envd.go` и `create_instance.go` совпали с отдельной branch-main копией.
Это исходники публичного upstream, не доказательство точной версии кода на хостах текущего развёртывания.
Секреты из окружения не читались; в кодовых фрагментах только алгоритм/поток исполнения.

## Deterministic envd bearer token derivation
`packages/api/internal/sandbox/sandbox_envd_secret.go:17-35`
```go
17: func NewAccessTokenGenerator(seedKey string) (*AccessTokenGenerator, error) {
18: 	if seedKey == "" {
19: 		return nil, errors.New("seed key is not set")
20: 	}
21:
22: 	return &AccessTokenGenerator{
23: 		hasher: keys.NewHMACSHA256Hashing([]byte(seedKey)),
24: 	}, nil
25: }
26:
27: func (g *AccessTokenGenerator) GenerateEnvdAccessToken(id api.SandboxID) (string, error) {
28: 	return g.hasher.Hash([]byte(id))
29: }
30:
31: func (g *AccessTokenGenerator) GenerateTrafficAccessToken(id api.SandboxID) (string, error) {
32: 	key := fmt.Sprintf("%s-%s", sandboxTrafficPrefix, id)
33:
34: 	return g.hasher.Hash([]byte(key))
35: }
```

## HMAC-SHA256 output encoding
`packages/shared/pkg/keys/hmac_sha256.go:1-32`
```go
1: package keys
2:
3: import (
4: 	"crypto/hmac"
5: 	"crypto/sha256"
6: 	"encoding/hex"
7: )
8:
9: type HMACSha256Hashing struct {
10: 	key []byte
11: }
12:
13: func NewHMACSHA256Hashing(key []byte) *HMACSha256Hashing {
14: 	return &HMACSha256Hashing{key: key}
15: }
16:
17: func (h *HMACSha256Hashing) Hash(content []byte) (string, error) {
18: 	mac := hmac.New(sha256.New, h.key)
19: 	_, err := mac.Write(content)
20: 	if err != nil {
21: 		return "", err
22: 	}
23:
24: 	return hex.EncodeToString(mac.Sum(nil)), nil
25: }
```

## Token regenerated on resume using sandboxID
`packages/api/internal/handlers/sandbox_resume.go:342-349`
```go
342: 		var envdAccessToken *string
343: 		if snap.EnvSecure {
344: 			accessToken, tokenErr := a.getEnvdAccessToken(build.EnvdVersion, sandboxID)
345: 			if tokenErr != nil {
346: 				return orchestrator.SandboxMetadata{}, tokenErr
347: 			}
348: 			envdAccessToken = &accessToken
349: 		}
```

## Legacy vs held init loops
`packages/orchestrator/pkg/sandbox/envd.go:122-148`
```go
122: // envdInitLoop names the readiness loop that served a start.
123: type envdInitLoop string
124:
125: const (
126: 	// envdInitLoopLegacy abandons each attempt at EnvdInitRequestTimeout and sends another.
127: 	envdInitLoopLegacy envdInitLoop = "legacy"
128: 	// envdInitLoopHeld holds one attempt for the whole budget and sends another only after
129: 	// a transport failure.
130: 	envdInitLoopHeld envdInitLoop = "held"
131: )
132:
133: const (
134: 	// envdUnobservedHeader carries envd's count of /init handlers that thawed the workload
135: 	// inline and completed after their client had gone, since the last served /init that
136: 	// carried it or the last freeze, whichever came later.
137: 	envdUnobservedHeader = "X-Envd-Init-Unobserved"
138: 	// envdClockCorrectionHeader carries, in whole milliseconds, the time envd added to the
139: 	// /init timestamp before its clock rules: its own time from reading the request body
140: 	// to those rules, sent whether or not they then stepped the clock.
141: 	envdClockCorrectionHeader = "X-Envd-Init-Clock-Correction"
142:
143: 	// envdInitGuestCountMax bounds a guest-reported count of /init handlers. Every handler
144: 	// is one request the orchestrator sent, and the legacy loop sends at most one per
145: 	// loopDelay, about 12,000 in a 60 s budget; a larger value is no count of ours and is
146: 	// not added.
147: 	envdInitGuestCountMax = 1 << 16
148: )
```

## Fields placed into /init
`packages/orchestrator/pkg/sandbox/envd.go:251-275`
```go
251: // envdInitRequest is the POST /init one start sends. Its body and headers are fixed for
252: // the start; each attempt stamps its own Timestamp when it marshals the body.
253: type envdInitRequest struct {
254: 	address     string
255: 	body        envd.PostInitJSONBody
256: 	accessToken *string
257: }
258:
259: func (s *Sandbox) newEnvdInitRequest(address string) *envdInitRequest {
260: 	return &envdInitRequest{
261: 		address: address,
262: 		body: envd.PostInitJSONBody{
263: 			LifecycleID:    s.LifecycleID,
264: 			EnvVars:        s.Config.Envd.Vars,
265: 			HyperloopIP:    s.config.NetworkConfig.OrchestratorInSandboxIPAddress,
266: 			AccessToken:    utils.DerefOrDefault(s.Config.Envd.AccessToken, ""),
267: 			DefaultUser:    utils.DerefOrDefault(s.Config.Envd.DefaultUser, ""),
268: 			DefaultWorkdir: utils.DerefOrDefault(s.Config.Envd.DefaultWorkdir, ""),
269: 			VolumeMounts:   s.convertMounts(s.Config.VolumeMounts),
270: 			CaBundle:       s.CABundle,
271: 			// A snapshot may resume with a different number of guest CPUs online.
272: 			CpuCount: s.guestCpuCount(),
273: 		},
274: 		accessToken: s.Config.Envd.AccessToken,
275: 	}
```

## Legacy infinite retry loop and per-attempt timeout
`packages/orchestrator/pkg/sandbox/envd.go:301-344`
```go
301: // doRequestWithInfiniteRetries does a request with infinite retries until the context is done.
302: // The parent context must be bounded — by a deadline/timeout, or by a cancel
303: // the caller races against sandbox liveness (WaitForEnvd, bestEffortEnvdReinit).
304: func (s *Sandbox) doRequestWithInfiniteRetries(
305: 	ctx context.Context,
306: 	initRequest *envdInitRequest,
307: ) (*http.Response, envdInitAttempts, error) {
308: 	var attempts envdInitAttempts
309:
310: 	for {
311: 		timestamp := time.Now()
312: 		body, err := initRequest.marshal(timestamp)
313: 		if err != nil {
314: 			return nil, attempts, err
315: 		}
316:
317: 		attempts.count++
318: 		var phase attemptPhase
319: 		reqCtx, cancel := context.WithTimeout(phase.trace(ctx), s.internalConfig.EnvdInitRequestTimeout)
320: 		request, err := initRequest.newHTTPRequest(reqCtx, body)
321: 		if err != nil {
322: 			cancel()
323:
324: 			return nil, attempts, err
325: 		}
326:
327: 		response, err := sandboxHttpClient.Do(request)
328: 		if err == nil {
329: 			response.Body = &cancelOnClose{ReadCloser: response.Body, cancel: cancel}
330: 			attempts.servedAge = time.Since(timestamp)
331:
332: 			return response, attempts, nil
333: 		}
334: 		cancel()
335:
336: 		attempts.fail(phase.phase())
337:
338: 		select {
339: 		case <-ctx.Done():
340: 			return nil, attempts, fmt.Errorf("%w with cause: %w", ctx.Err(), context.Cause(ctx))
341: 		case <-time.After(loopDelay):
342: 		}
343: 	}
344: }
```

## Held/legacy selection
`packages/orchestrator/pkg/sandbox/envd.go:847-867`
```go
847: 	baseURL := s.envdServerURL()
848: 	initRequest := s.newEnvdInitRequest(baseURL + "/init")
849:
850: 	var (
851: 		response *http.Response
852: 		err      error
853: 	)
854: 	if held {
855: 		heldClient, clientErr := newHeldInitClient(baseURL, s.envdInitConnectTimeout(ctx), opts.budget)
856: 		if clientErr != nil {
857: 			return fmt.Errorf("failed to init envd: %w", clientErr)
858: 		}
859: 		defer heldClient.close()
860:
861: 		if s.skipThaw {
862: 			initRequest.body.Thaw = envd.Skip
863: 		}
864: 		response, attempts, err = s.doHeldInit(ctx, heldClient, initRequest, countStart, opts.reinit)
865: 	} else {
866: 		response, attempts, err = s.doRequestWithInfiniteRetries(ctx, initRequest)
867: 	}
```

## Held-init gate: flag plus envd >= 0.10.0
`packages/orchestrator/pkg/sandbox/envd_held_init.go:47-60`
```go
47: // useHeldInit decides the readiness loop for one start: the held request when
48: // envd-init-held-request is on for this sandbox and the gate version is at or above
49: // MinEnvdVersionForHeldInit. An unparseable version reads as below it.
50: func (s *Sandbox) useHeldInit(ctx context.Context) bool {
51: 	if s.featureFlags == nil {
52: 		return false
53: 	}
54: 	if !s.featureFlags.BoolFlag(ctx, featureflags.EnvdInitHeldRequestFlag, sandboxLDContext(s.Runtime, s.Config)) {
55: 		return false
56: 	}
57:
58: 	ok, err := utils.IsGTEVersion(s.envdGateVersion(), utils.MinEnvdVersionForHeldInit)
59:
60: 	return err == nil && ok
```

## Pause/freeze race and legacy path caveat
`packages/orchestrator/pkg/sandbox/envd_reinit.go:19-51`
```go
19: // errEnvdReinitCut is the cause a post-checkpoint re-init is cancelled with when a Pause
20: // stops it or a fresh re-init replaces it, and what initEnvd returns, wrapped, when either
21: // kept it from completing: before its gate chose a loop, or with its /init unwritten or in
22: // flight. The handle's cutBy names which.
23: var errEnvdReinitCut = errors.New("envd re-init cut")
24:
25: // envdReinit is the post-checkpoint re-init's handle, published on the sandbox before its
26: // goroutine starts, so that a following Pause can stop it before freezing. A held re-init
27: // that wrote its /init after the pre-pause freeze would have envd serve it behind that
28: // freeze, and its handler would thaw the workload the snapshot is about to capture.
29: //
30: // A Pause marks the handle stopped, so that no further write starts: the held loop checks
31: // the mark under mu before each /init it writes. It then cancels a held re-init's context,
32: // whatever it has written, and waits for it to return. A re-init that has not yet chosen
33: // its loop is only marked: if it then chooses the held loop, begin refuses it and it
34: // writes nothing. An /init already written
35: // cannot thaw the freeze that follows on an envd at or above MinEnvdVersionForHeldInit:
36: // its handler read envd's freeze generation when it entered, the freeze advances it, and
37: // the handler's thaw is withheld. Only a held re-init is cut: a legacy-loop re-init is left
38: // as it is, so its /init, if envd serves it after the pre-pause freeze, may still thaw that
39: // freeze -- today's behaviour, which the flag leaves unchanged.
40: //
41: // Every fresh re-init replaces the handle before it (startEnvdReinit): begin then refuses
42: // that one on either loop, a held one in flight is cancelled, and none writes again, so a
43: // re-init still undecided or in flight when a fresh one starts never writes beside it. One
44: // that chose the legacy loop by then is left to run, as before. A Pause's cleanup replaces
45: // the handle it stopped before starting a fresh one, and starts none when the handle was
46: // left to run or already replaced.
47: //
48: // A Pause's cut also holds publication (envdReinitHolds): from the cut until its freeze
49: // landed, or until it gave up before freezing, no fresh re-init is published, so the
50: // handle the cut stopped is the one in place when the guest freezes. A start under a hold
51: // starts nothing; the Pause holding it re-syncs the clock itself once its outcome is known.
```

## Post-checkpoint re-init and slot-reuse hazard/cancellation
`packages/orchestrator/pkg/sandbox/envd_reinit.go:265-313`
```go
265: // bestEffortEnvdReinit re-runs the envd /init a real resume makes, after an
266: // in-place resume (success or error-cleanup path), or from the cleanup of a
267: // Pause that cut one (cutEnvdReinitForPause). The FC-paused window
268: // stopped the guest's clocks; envd steps CLOCK_REALTIME from /init's host
269: // timestamp when it lags by >50ms — less than a single checkpoint's pause
270: // window — so without this every checkpoint leaves the guest's wall clock
271: // behind by the paused duration and repeated checkpoints accumulate the
272: // drift. Best-effort: it is the same /init every resume already makes against
273: // a live envd, and a failure only leaves the clock lagging until the next
274: // resume. initCtx is detached from the request so a dying request ctx can't
275: // skip it.
276: //
277: // The episode budget is the envd-timeout flag (~10s) — the same bound a real
278: // resume gives WaitForEnvd — NOT EnvdInitRequestTimeout: that 50ms value is
279: // the PER-ATTEMPT deadline inside initEnvd's retry loop, calibrated for
280: // fail-fast-and-retry, and using it as the total would allow exactly one
281: // attempt against a guest that is busy working through its post-freeze
282: // backlog. initCtx carries the /init, so nothing of the re-init outlives that
283: // budget.
284: func (s *Sandbox) bestEffortEnvdReinit(ctx, initCtx context.Context, r *envdReinit) {
285: 	defer r.cancel(nil)
286:
287: 	budget := time.Duration(s.featureFlags.IntFlag(ctx, featureflags.EnvdTimeoutMilliseconds)) * time.Millisecond
288:
289: 	// The same race WaitForEnvd runs around this exact retry loop: bound it on
290: 	// sandbox LIVENESS, not just time. Detached from the request, a re-init
291: 	// that only times out would outlive a sandbox killed mid-budget — and
292: 	// outlive the network pool's 3s slot drain, POSTing this sandbox's /init
293: 	// body (access token, env vars, CA bundle) at whichever tenant is handed
294: 	// the recycled slot IP next.
295: 	go func() {
296: 		select {
297: 		case <-time.After(budget):
298: 			r.cancel(errors.New("envd re-init budget exceeded"))
299: 		case <-initCtx.Done():
300: 			return
301: 		case <-s.process.Exit.Done():
302: 			// Exit.Error() is nil for every orchestrator-initiated teardown
303: 			// (SIGTERM/SIGKILL both store nil); a nil %w renders as
304: 			// %!w(<nil>), garbling the dominant cause string.
305: 			if exitErr := s.process.Exit.Error(); exitErr != nil {
306: 				r.cancel(fmt.Errorf("%w: %w", ErrFcProcessExited, exitErr))
307: 			} else {
308: 				r.cancel(ErrFcProcessExited)
309: 			}
310: 		}
311: 	}()
312:
313: 	err := s.initEnvd(initCtx, StartTypeResume, false, envdInitOptions{budget: budget, reinit: r})
```

## Tests: legacy re-init left alone; held init cancelled on Firecracker exit
`packages/orchestrator/pkg/sandbox/envd_reinit_test.go:298-340`
```go
298: 	t.Run("a legacy re-init is left as it is", func(t *testing.T) { //nolint:paralleltest // see TestReinitCut
299: 		e := newHeldEnvd(t)
300: 		arrived := make(chan struct{})
301: 		release, releaseInit := releaser(t)
302: 		served := e.init
303: 		e.init = func(w http.ResponseWriter, n int, read func() envd.PostInitJSONBody) {
304: 			close(arrived)
305: 			<-release
306: 			served(w, n, read)
307: 		}
308: 		s, _, _ := newReinitSandbox(t, e.srv.URL, false, 10*time.Second)
309: 		s.internalConfig.EnvdInitRequestTimeout = 10 * time.Second
310: 		before := reinitCuts(t)
311:
312: 		s.startEnvdReinit(t.Context())
313: 		<-arrived
314: 		cutReturnsPromptly(t, s)
315: 		releaseInit()
316: 		<-s.envdReinit.Load().done
317:
318: 		assert.Equal(t, []string{"/init"}, e.paths(), "the legacy re-init was served")
319: 		assert.Empty(t, cutDelta(t, before))
320: 	})
321:
322: 	t.Run("a Firecracker exit during the held /init is counted as a kill", func(t *testing.T) { //nolint:paralleltest // see TestReinitCut
323: 		e := newHeldEnvd(t)
324: 		arrived := make(chan struct{})
325: 		release, _ := releaser(t)
326: 		e.init = func(_ http.ResponseWriter, _ int, read func() envd.PostInitJSONBody) {
327: 			read()
328: 			close(arrived)
329: 			<-release
330: 		}
331: 		s, _, exit := newReinitSandbox(t, e.srv.URL, true, time.Minute)
332: 		before := reinitCuts(t)
333:
334: 		s.startEnvdReinit(t.Context())
335: 		<-arrived
336: 		require.NoError(t, exit.SetError(nil))
337: 		<-s.envdReinit.Load().done
338:
339: 		assert.Equal(t, map[string]int64{"kill": 1}, cutDelta(t, before))
340: 	})
```

## Resume node affinity and timed-out remap call
`packages/api/internal/orchestrator/create_instance.go:456-510`
```go
456: 	// Only a resume is pinned to the node its snapshot was taken on; any other
457: 	// start from a snapshot (a fork) is placed like a new sandbox.
458: 	affinityRequested := isResume && sbxData.NodeID != nil
459: 	if affinityRequested {
460: 		telemetry.ReportEvent(ctx, "Placing sandbox on the node where the snapshot was taken")
461:
462: 		clusterID := clusters.WithClusterFallback(team.ClusterID)
463: 		node = o.GetNode(clusterID, *sbxData.NodeID)
464: 		if node != nil && !node.CanAcceptNewRequests() {
465: 			node = nil
466: 		}
467: 		// Snapshot affinity skips the candidate filter below, and the origin node
468: 		// can drift off the snapshot's own side of the partition when a timed-out
469: 		// resume remaps it. Vetted here so it cannot outrank the partition.
470: 		if node != nil && !hostIsolation.Allows(node) {
471: 			node = nil
472: 		}
473: 	}
474:
475: 	nodeClusterID := clusters.WithClusterFallback(team.ClusterID)
476: 	clusterNodes := o.GetClusterNodes(nodeClusterID)
477:
478: 	if hostIsolation.Enabled() {
479: 		isolatedCandidates := hostIsolation.FilterNodes(clusterNodes)
480: 		// Recorded because the partition starving placement surfaces as an
481: 		// ordinary "no nodes available", which alone does not say the fence
482: 		// caused it.
483: 		telemetry.SetAttributes(ctx,
484: 			attribute.Bool("placement.host_isolation.isolated_origin", hostIsolation.IsolatedOrigin()),
485: 			attribute.Int("placement.host_isolation.nodes_before", len(clusterNodes)),
486: 			attribute.Int("placement.host_isolation.nodes_after", len(isolatedCandidates)),
487: 		)
488:
489: 		clusterNodes = isolatedCandidates
490: 	}
491:
492: 	allLabels, labelFilteringEnabled := o.generateRequiredNodeLabels(ctx, sandboxID, team, sbxData)
493:
494: 	requirements := placement.Requirements{
495: 		CPU: cpuRequirement,
496: 		Memory: placement.MemoryRequirement{
497: 			Limit: float64(o.featureFlagsClient.IntFlag(ctx, featureflags.PlacementHugepageLimitPercent, featureflags.TeamContext(team.ID.String()), featureflags.SandboxContext(sandboxID))) / 100,
498: 		},
499: 	}
500:
501: 	placed, err := placement.PlaceSandboxCompletingStartedCreate(ctx, o.placementAlgorithm, clusterNodes, node, sbxRequest, requirements, labelFilteringEnabled, allLabels, completeStartedCreateUntil)
502: 	if err != nil {
503: 		if isResume && placed.TimedOut {
504: 			// Remap by the snapshot's own sandbox ID: when forking, the started
505: 			// sandbox ID has no snapshot row and the remap would silently no-op.
506: 			snapshotSandboxID := sandboxID
507: 			if sbxData.SnapshotSandboxID != "" {
508: 				snapshotSandboxID = sbxData.SnapshotSandboxID
509: 			}
510: 			o.maybeRemapResumeOriginNode(ctx, snapshotSandboxID, team, sbxData.NodeID, placed.WarmedNode)
```

## Feature-flagged remap of snapshot origin node after timeout
`packages/api/internal/orchestrator/create_instance.go:653-705`
```go
653: // maybeRemapResumeOriginNode repoints the snapshot's origin_node_id to the
654: // fallback node a resume timed out on. Pinning the next resume attempt to avoid
655: // re-pulling the snapshot onto another node and spraying load across the cluster
656: //
657: // It only acts on placement timeouts (warmedNode is nil otherwise), and only
658: // when the warming node differs from the origin we already tried. The write runs
659: // on a detached context because the request context is already past its deadline
660: // (that is why placement timed out).
661: func (o *Orchestrator) maybeRemapResumeOriginNode(ctx context.Context, sandboxID string, team *teamtypes.Team, originNodeID *string, warmedNode *nodemanager.Node) {
662: 	if warmedNode == nil {
663: 		return
664: 	}
665:
666: 	newNode := warmedNode
667: 	if originNodeID != nil && *originNodeID == newNode.ID {
668: 		return
669: 	}
670:
671: 	// The request context is already past its deadline (that is why placement
672: 	// timed out), so detach it for everything below: the feature-flag read, the
673: 	// DB write, cache invalidation, the counter, and logging would all otherwise
674: 	// observe a cancelled context.
675: 	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
676: 	defer cancel()
677:
678: 	if !o.featureFlagsClient.BoolFlag(wctx, featureflags.ResumeOriginNodeRemapFlag, featureflags.TeamContext(team.ID.String()), featureflags.SandboxContext(sandboxID)) {
679: 		return
680: 	}
681:
682: 	if err := o.sqlcDB.UpdateSnapshotOriginNode(wctx, queries.UpdateSnapshotOriginNodeParams{
683: 		OriginNodeID: newNode.ID,
684: 		SandboxID:    sandboxID,
685: 	}); err != nil {
686: 		logger.L().Warn(wctx, "failed to remap resume origin node",
687: 			zap.Error(err),
688: 			logger.WithSandboxID(sandboxID),
689: 		)
690:
691: 		return
692: 	}
693:
694: 	// Drop the cached snapshot so the next resume reads the new origin node.
695: 	o.snapshotCache.Invalidate(wctx, sandboxID)
696: 	o.resumeOriginNodeRemapCounter.Add(wctx, 1, metric.WithAttributes(telemetry.WithTeamID(team.TeamID())))
697:
698: 	oldNodeID := ""
699: 	if originNodeID != nil {
700: 		oldNodeID = *originNodeID
701: 	}
702:
703: 	logger.L().Info(wctx, "remapped resume origin node to the node a previous resume timed out on",
704: 		logger.WithSandboxID(sandboxID),
705: 		zap.String("old_origin_node_id", oldNodeID),
```

## ExecutionID vs per-Firecracker LifecycleID
`packages/orchestrator/pkg/sandbox/sandbox.go:419-424`
```go
419: 	// LifecycleID is a unique identifier for each Firecracker process.
420: 	// It is used internally by the orchestrator for map eviction guards
421: 	// and proxy connection pooling. Unlike ExecutionID (which is stable
422: 	// across checkpoints and shared with the API), LifecycleID changes
423: 	// every time a new Firecracker VM is started.
424: 	LifecycleID string
```

## Fresh lifecycle UUID allocation
`packages/orchestrator/pkg/sandbox/sandbox.go:1090-1098`
```go
1090: 	lifecycleID := uuid.NewString()
1091:
1092: 	sandboxFiles := template.Files().NewSandboxFiles(runtime.SandboxID)
1093: 	cleanup.Add(ctx, cleanupFiles(f.config, sandboxFiles))
1094:
1095: 	// Fail before network or rootfs setup if a required CPU limit is unavailable.
1096: 	cgroupHandle, err := createCgroup(ctx, f.cgroupManager, sandboxFiles.SandboxCgroupName(), config.ConfiguredVmVcpus > config.Vcpu)
1097: 	if err != nil {
1098: 		return nil, err
```

## Throwaway resume is isolated/unregistered
`packages/orchestrator/pkg/server/prefetch_harvest.go:115-169`
```go
115: // harvestResumer resumes the throwaway instance the harvest records its trace
116: // from. It is an interface so the orchestration can be unit-tested with a fake.
117: type harvestResumer interface {
118: 	// ResumeForHarvest resumes a throwaway, network-isolated, unregistered copy
119: 	// of the snapshot; the caller reaps the returned instance.
120: 	ResumeForHarvest(ctx context.Context, t sbxtemplate.Template, config *sandbox.Config, runtime sandboxtypes.RuntimeMetadata, startedAt, endAt time.Time, envdVersion string) (harvestInstance, error)
121: }
122:
123: // harvestInstance is the subset of a resumed sandbox the harvest uses.
124: type harvestInstance interface {
125: 	MemoryPrefetchData(ctx context.Context) (block.PrefetchData, error)
126: 	Stop(ctx context.Context) error
127: 	Close(ctx context.Context) error
128: }
129:
130: // harvestTemplates is the subset of the template cache the harvest uses.
131: type harvestTemplates interface {
132: 	GetTemplatePinned(ctx context.Context, buildID string, isSnapshot, isBuilding bool, opts ...sbxtemplate.GetTemplateOpts) (sbxtemplate.Template, func(), error)
133: 	UpdateMetadata(ctx context.Context, buildID string, meta metadata.Template) error
134: }
135:
136: // harvestUpload is the subset of the in-flight snapshot upload the harvest waits on.
137: type harvestUpload interface {
138: 	Wait(ctx context.Context) error
139: }
140:
141: // factoryResumer adapts *sandbox.Factory to harvestResumer, applying the
142: // throwaway-specific resume options (deny egress, skip live registration) so the
143: // orchestration itself stays agnostic of them.
144: type factoryResumer struct {
145: 	factory *sandbox.Factory
146: }
147:
148: func (r factoryResumer) ResumeForHarvest(ctx context.Context, t sbxtemplate.Template, config *sandbox.Config, runtime sandboxtypes.RuntimeMetadata, startedAt, endAt time.Time, envdVersion string) (harvestInstance, error) {
149: 	// Network-isolated, unregistered and left frozen; the set is asserted in package
150: 	// sandbox.
151: 	opts := append(sandbox.ThrowawayResumeOptions(), sandbox.WithInheritedEnvdVersion(envdVersion))
152: 	sbx, err := r.factory.ResumeSandbox(
153: 		ctx,
154: 		t,
155: 		config,
156: 		runtime,
157: 		startedAt,
158: 		endAt,
159: 		// Throwaway: no API config to store (it is never restarted/addressable).
160: 		nil,
161: 		opts...,
162: 	)
163: 	if err != nil {
164: 		// Return a nil interface, not a typed-nil *Sandbox, on error.
165: 		return nil, err
166: 	}
167:
168: 	return sbx, nil
169: }
```

## Harvest feature gates default off
`packages/orchestrator/pkg/server/prefetch_harvest.go:200-240`
```go
200: // harvestResumePrefetchAsync records a resume page-fault trace for a snapshot
201: // that was written without a real resume — a pause, or an in-place checkpoint
202: // — and (optionally) persists it as a prefetch mapping, so the next resume or
203: // launch from that snapshot can replay it.
204: //
205: // It is the analogue of the resume+harvest the resume-fresh checkpoint does,
206: // with these differences: the resumed instance is a throwaway (network
207: // isolated, kept out of the live registry, never promoted to a live sandbox),
208: // and the harvested mapping is carried through metadata that otherwise drops
209: // Prefetch (the same-version pause metadata, or the in-place checkpoint's,
210: // which deliberately records no live-tracker trace).
211: //
212: // It is best-effort and runs AFTER the RPC has returned, alongside the
213: // in-flight snapshot upload: it never affects the pause or checkpoint result,
214: // the local snapshot is already in the cache, and the consume path waits for
215: // the upload before touching metadata. Both gates default off, so this is a
216: // no-op until explicitly enabled. source labels the harvest metrics so the two
217: // producers can be read apart.
218: func (s *Server) harvestResumePrefetchAsync(
219: 	ctx context.Context,
220: 	sbx *sandbox.Sandbox,
221: 	res *snapshotResult,
222: 	buildID string,
223: 	objectMetadata storage.ObjectMetadata,
224: 	source harvestSource,
225: ) {
226: 	// Flag checks run synchronously (ctx still carries the per-sandbox LD
227: 	// context the Pause handler attached) before we detach into a goroutine.
228: 	if !s.featureFlags.BoolFlag(ctx, featureflags.PauseResumePrefetchHarvestFlag) {
229: 		return
230: 	}
231:
232: 	timeoutMs := s.featureFlags.IntFlag(ctx, featureflags.PauseResumePrefetchHarvestTimeoutMsFlag)
233: 	// Guard against a misconfigured (zero/negative) flag value, which would yield
234: 	// an already-expired context and silently skip every harvest.
235: 	timeoutMs = clampHarvestTimeoutMs(timeoutMs)
236: 	// When off, the harvest still runs and logs its trace size but persists
237: 	// nothing — so resumes are unaffected and we can validate harvest behaviour
238: 	// with no customer-visible change before enabling prefetch on resume.
239: 	consume := s.featureFlags.BoolFlag(ctx, featureflags.PauseResumePrefetchConsumeFlag)
240: 	harvester := s.newPrefetchHarvester()
```

## Held-init body is created only after 100-continue; retry semantics
`packages/orchestrator/pkg/sandbox/envd_held_init.go:282-355`
```go
282: // mintedInitBody is a held /init's body, which does not exist until the transport reads it.
283: // The request carries Expect: 100-continue, so the transport reads it only once envd's
284: // handler has asked for the body; its timestamp is minted then, after the guest's accept
285: // queue, the header parse and the dispatch, which on a slow resume are most of the time a
286: // request spends before envd applies it. Its length is unknown up front, so the body is
287: // sent chunked.
288: type mintedInitBody struct {
289: 	mu     sync.Mutex
290: 	body   envd.PostInitJSONBody
291: 	minted time.Time
292: 	r      *bytes.Reader
293: 	err    error
294: }
295:
296: func newMintedInitBody(body envd.PostInitJSONBody) *mintedInitBody {
297: 	return &mintedInitBody{body: body}
298: }
299:
300: func (b *mintedInitBody) Read(p []byte) (int, error) {
301: 	b.mu.Lock()
302: 	defer b.mu.Unlock()
303:
304: 	if b.r == nil && b.err == nil {
305: 		b.minted = time.Now()
306: 		b.body.Timestamp = b.minted
307:
308: 		encoded, err := json.Marshal(b.body)
309: 		if err != nil {
310: 			b.err = err
311: 		} else {
312: 			b.r = bytes.NewReader(encoded)
313: 		}
314: 	}
315: 	if b.err != nil {
316: 		return 0, b.err
317: 	}
318:
319: 	return b.r.Read(p)
320: }
321:
322: func (b *mintedInitBody) Close() error { return nil }
323:
324: // mintedAt is when the body's timestamp was minted, and false when the transport never read
325: // the body: envd answered before it asked for one.
326: func (b *mintedInitBody) mintedAt() (time.Time, bool) {
327: 	b.mu.Lock()
328: 	defer b.mu.Unlock()
329:
330: 	return b.minted, b.r != nil
331: }
332:
333: // newHeldHTTPRequest builds one held attempt's POST /init with a body minted when read.
334: func (r *envdInitRequest) newHeldHTTPRequest(ctx context.Context) (*http.Request, *mintedInitBody, error) {
335: 	body := newMintedInitBody(r.body)
336:
337: 	request, err := http.NewRequestWithContext(ctx, http.MethodPost, r.address, body)
338: 	if err != nil {
339: 		return nil, nil, err
340: 	}
341: 	request.Header.Set("Expect", "100-continue")
342: 	if r.accessToken != nil {
343: 		request.Header.Set("X-Access-Token", *r.accessToken)
344: 	}
345:
346: 	return request, body, nil
347: }
348:
349: // doHeldInit sends one /init and waits for it under the parent context alone, re-sending
350: // only after a transport failure. Each attempt dials first, so the request's headers are
351: // written on a connection that is already up, and its body, timestamp included, only once
352: // envd's handler asks for it. A failed connect is retried after loopDelay, as the legacy
353: // loop does while envd is not yet listening; a failure after the connection was up is
354: // retried on a new connection.
355: func (s *Sandbox) doHeldInit(
```


## Held-init loop retry branch
`packages/orchestrator/pkg/sandbox/envd_held_init.go:355-405`
```go
355: func (s *Sandbox) doHeldInit(
356: 	ctx context.Context,
357: 	h *heldInitClient,
358: 	initRequest *envdInitRequest,
359: 	countStart bool,
360: 	reinit *envdReinit,
361: ) (*http.Response, envdInitAttempts, error) {
362: 	var attempts envdInitAttempts
363:
364: 	for {
365: 		if reinit != nil && !reinit.mayWrite() {
366: 			return nil, attempts, errEnvdReinitCut
367: 		}
368: 		attempts.count++
369:
370: 		dialStart := time.Now()
371: 		conn, err := h.dial(ctx)
372: 		dialed := time.Since(dialStart)
373: 		if err != nil {
374: 			attempts.fail(envdInitPhaseConnect)
375: 			s.recordSlowDial(ctx, countStart, dialed, string(envdInitPhaseConnect))
376: 		} else {
377: 			h.handOff(conn)
378:
379: 			var phase attemptPhase
380: 			request, body, err := initRequest.newHeldHTTPRequest(phase.trace(ctx))
381: 			if err != nil {
382: 				return nil, attempts, err
383: 			}
384:
385: 			response, err := h.do(request)
386: 			if err == nil {
387: 				if minted, ok := body.mintedAt(); ok {
388: 					attempts.servedAge = time.Since(minted)
389: 				}
390: 				s.recordSlowDial(ctx, countStart, dialed, "success")
391:
392: 				return response, attempts, nil
393: 			}
394:
395: 			failed := phase.heldPhase()
396: 			attempts.fail(failed)
397: 			s.recordSlowDial(ctx, countStart, dialed, string(failed))
398: 		}
399:
400: 		select {
401: 		case <-ctx.Done():
402: 			return nil, attempts, fmt.Errorf("%w with cause: %w", ctx.Err(), context.Cause(ctx))
403: 		case <-time.After(loopDelay):
404: 		}
405: 	}
```


## ExecutionID generation and in-place checkpoint identity

### Ordinary API create assigns a fresh ExecutionID
`packages/api/internal/handlers/sandbox.go:60-80`
```go
60: 	isResume bool,
61: 	demandFilesystemBoot bool,
62: 	mcp api.Mcp,
63: 	options ...orchestrator.CreateOption,
64: ) (sandbox.Sandbox, *api.APIError) {
65: 	startTime := time.Now()
66: 	endTime := startTime.Add(timeout)
67:
68: 	// Unique ID for the execution (from start/resume to stop/pause)
69: 	executionID := uuid.New().String()
70:
71: 	creationMeta := buildCreationMetadata(team, requestHeader, isResume, mcp)
72:
73: 	sbx, instanceErr := a.orchestrator.CreateSandbox(
74: 		ctx,
75: 		sandboxID,
76: 		executionID,
77: 		team,
78: 		getSandboxData,
79: 		startTime,
80: 		endTime,
```

### In-place checkpoint keeps ExecutionID
`packages/orchestrator/pkg/server/checkpoint_steps.go:37-61`
```go
37: func (r serverResumeFreshSteps) template(ctx context.Context, sbx *sandbox.Sandbox, buildID string) (sbxtemplate.Template, func(), error) {
38: 	// Pinned for the resumed sandbox's lifetime; see the Create path for why.
39: 	return r.s.templateCache.GetTemplatePinned(ctx, buildID, true, false,
40: 		sbxtemplate.GetTemplateOpts{MaxSandboxLengthHours: sbx.Config.MaxSandboxLengthHours})
41: }
42:
43: func (r serverResumeFreshSteps) resume(ctx context.Context, template sbxtemplate.Template, sbx *sandbox.Sandbox) (*sandbox.Sandbox, error) {
44: 	// Resume the sandbox keeping the same ExecutionID (stable identity for
45: 	// the API, routing catalog, and analytics) but with a fresh LifecycleID
46: 	// so the old sandbox's cleanup goroutine won't
47: 	// accidentally evict the resumed sandbox from the map.
48: 	return r.s.sandboxFactory.ResumeSandbox(
49: 		ctx,
50: 		template,
51: 		sbx.Config,
52: 		sandboxtypes.RuntimeMetadata{
53: 			TemplateID:  sbx.Runtime.TemplateID,
54: 			SandboxID:   sbx.Runtime.SandboxID,
55: 			ExecutionID: sbx.Runtime.ExecutionID,
56: 			TeamID:      sbx.Runtime.TeamID,
57: 			BuildID:     sbx.Runtime.BuildID,
58: 			SandboxType: sbx.Runtime.SandboxType,
59: 		},
60: 		sbx.GetStartedAt(),
61: 		sbx.GetEndAt(),
```

### Checkpoint path keeps same execution and Firecracker process
`packages/orchestrator/pkg/server/sandboxes.go:1654-1672`
```go
1654: 	return nil
1655: }
1656:
1657: // checkpointInPlace pauses the sandbox, caches the checkpoint, and resumes it
1658: // IN PLACE — the sandbox keeps running (same ExecutionID and FC process), so
1659: // there is no MarkStopping / stopSandboxAsync / resume-fresh here; Pause
1660: // resumes it before returning, and no SetStopReason / SetStoppedAt is
1661: // recorded for it (both are first-call-wins, and recording them for a
1662: // sandbox that keeps running would mislabel its eventual real stop).
1663: //
1664: // The ONE exception to all of the above is ErrSandboxLost: when the in-place
1665: // resume itself fails, Pause tears the sandbox down (Close, with
1666: // StopReasonKilled set by Pause before the Close) — this function then emits
1667: // the killed event/counter itself, because the teardown's cleanup has already
1668: // MarkStopping-ed the sandbox out of the live map, so the API's follow-up
1669: // Delete finds nothing to attribute.
1670: // checkpointInPlace reports, next to the reply, whether the memory export
1671: // went through the CoW window (true) or the synchronous copy (false); false
1672: // as well when the snapshot failed before that was decided.
```
