// Command whatserverd is the whatserver2 API server.
//
// Run with no arguments to serve. The bootstrap subcommand creates a tenant and
// prints an API key, which is how a fresh installation gets its first
// credential.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/authapi"
	"whatserver2/internal/blob"
	"whatserver2/internal/bus"
	"whatserver2/internal/config"
	"whatserver2/internal/domain"
	"whatserver2/internal/ingest"
	"whatserver2/internal/media"
	"whatserver2/internal/migrate"
	"whatserver2/internal/obs"
	"whatserver2/internal/pg"
	"whatserver2/internal/ratelimit"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
	"whatserver2/internal/webui"
	"whatserver2/internal/wsapi"
)

func main() {
	var err error
	switch {
	case len(os.Args) > 1 && os.Args[1] == "bootstrap":
		err = bootstrap(os.Args[2:])
	case len(os.Args) > 1 && os.Args[1] == "tenants":
		err = listTenants()
	case len(os.Args) > 1 && os.Args[1] == "key":
		err = issueKey(os.Args[2:])
	case len(os.Args) > 1 && os.Args[1] == "device-key":
		err = deviceKey(os.Args[2:])
	case len(os.Args) > 1 && os.Args[1] == "invite":
		err = issueInvite(os.Args[2:])
	case len(os.Args) > 1 && os.Args[1] == "reset-archive":
		err = resetArchive(os.Args[2:])
	case len(os.Args) > 1 && os.Args[1] == "retention":
		err = setRetention(os.Args[2:])
	case len(os.Args) > 1 && os.Args[1] == "erase":
		err = eraseContact(os.Args[2:])
	case len(os.Args) > 1 && os.Args[1] == "reproject":
		err = reproject(os.Args[2:])
	default:
		err = serve()
	}
	if err != nil {
		// The logger may not exist yet if configuration itself failed.
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

// app holds everything the server needs, wired once.
type app struct {
	cfg      config.Config
	log      *slog.Logger
	metrics  *obs.Metrics
	pools    *pg.Pools
	devices  *store.Devices
	apiKeys  *store.APIKeys
	keys     *store.Keys
	messages *store.Messages
	receipts *store.Receipts
	contacts *store.Contacts
	unread   *store.Unread
	groups   *store.Groups
	media    *store.Media
	blob     *blob.Store
	worker   *media.Worker
	avatars  *media.AvatarWorker
	retrier  *media.Retrier
	bus      *bus.Bus
	registry *wa.Registry
	router   *ingest.Router
	ws       *wsapi.Server
	web      *webui.Handler
	// limits bounds sign-in attempts, shared by the HTTP auth endpoints and
	// the websocket hello so a script cannot alternate between the two.
	limits *ratelimit.Auth
}

// setup opens every dependency and runs migrations. The returned close
// function tears them down in reverse.
func setup(ctx context.Context, withWA bool) (*app, func(), error) {
	// Convenience for local development. Real environment variables always
	// take precedence, and a missing file is not an error.
	if err := config.LoadDotEnv(".env"); err != nil {
		return nil, nil, err
	}
	cfg, err := config.Load()
	if err != nil {
		return nil, nil, err
	}
	lg := obs.NewLogger(cfg.Log.Level, cfg.Log.Format)

	pools, err := pg.Open(ctx, cfg.Postgres)
	if err != nil {
		return nil, nil, err
	}
	closers := []func(){pools.Close}
	closeAll := func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
	}

	// Row-level security is the whole of tenant isolation, and a superuser
	// reads through it. Refused in prod; in dev it is said out loud, because
	// the tests would keep passing and nothing else would ever mention it.
	if err := pools.CheckRole(ctx); err != nil {
		if cfg.Env.IsProd() {
			closeAll()
			return nil, nil, err
		}
		lg.Warn("the database role bypasses row-level security; this would be refused in prod",
			"error", err)
	}

	if err := migrate.Run(ctx, pools.API, lg); err != nil {
		closeAll()
		return nil, nil, err
	}

	a := &app{
		cfg: cfg, log: lg, pools: pools,
		devices: store.NewDevices(pools.API),
		apiKeys: store.NewAPIKeys(pools.API),
		limits:  ratelimit.DefaultAuth(cfg.TrustedProxies),
	}

	if !withWA {
		return a, closeAll, nil
	}

	a.metrics = obs.NewMetrics()
	if err := pools.RegisterCollectors(a.metrics.Registry()); err != nil {
		closeAll()
		return nil, nil, err
	}

	// whatsmeow owns the schema of its own tables and runs its own migrations,
	// so it gets its own connection rather than sharing one of ours. Two
	// systems responsible for one database's shape is a bad trade.
	container, err := wa.OpenContainer(ctx, cfg.Postgres.DSN, lg)
	if err != nil {
		closeAll()
		return nil, nil, err
	}
	closers = append(closers, func() {
		if err := container.Close(); err != nil {
			lg.Warn("closing the session store failed", "error", err)
		}
	})

	a.bus = bus.New()
	a.messages = store.NewMessages(pools.API)
	a.receipts = store.NewReceipts(pools.API)
	a.contacts = store.NewContacts(pools.API)
	a.unread = store.NewUnread(pools.API)
	a.groups = store.NewGroups(pools.API)
	a.media = store.NewMedia(pools.API)
	a.keys = store.NewKeys(pools.API)

	// A store that is not configured comes back nil, and every method on it
	// answers ErrNotConfigured. Media then stays queued in the database rather
	// than being dropped, so configuring storage later drains a backlog
	// instead of starting from empty.
	a.blob, err = blob.New(cfg.Storage)
	if err != nil {
		closeAll()
		return nil, nil, err
	}
	if a.blob.Configured() {
		if err := a.blob.EnsureBucket(ctx, cfg.Storage.Region); err != nil {
			// Failing here rather than on the first attachment: a wrong bucket
			// name or a bad key is a boot-time mistake and should read like
			// one. A store that is merely down is a different mistake with a
			// different fix, and the message says which.
			closeAll()
			return nil, nil, storageBootError(err, cfg.Storage)
		}
	}

	a.retrier = &media.Retrier{
		Messages: a.messages,
		Media:    a.media,
		Devices: func(_ context.Context, _ uuid.UUID, deviceID string) (media.RetryClient, error) {
			dev, running := a.registry.Get(deviceID)
			if !running {
				return nil, errors.New("that device is not connected right now")
			}
			return dev.Client(), nil
		},
		Log: lg,
	}

	a.worker, err = media.New(media.Config{
		Media:   a.media,
		Blob:    a.blob,
		Fetcher: media.NewFetcher(cfg.Storage.MaxMediaBytes, ""),
		Tenants: a.activeTenants,
		Metrics: a.metrics,
		Log:     lg,
	})
	if err != nil {
		closeAll()
		return nil, nil, err
	}
	// The retrier nudges the same queue the download worker drains, so a
	// re-uploaded attachment is fetched without waiting for the next poll.
	a.retrier.Queue = a.worker

	// Declared before the registry so the status callback and the device
	// lookup can reach it, and assigned after, because they refer to each
	// other.
	var (
		ws       *wsapi.Server
		registry *wa.Registry
	)

	// The router resolves a device to its tenant through the registry, which
	// is the only thing that knows what is running in this process.
	router, err := ingest.NewRouter(ingest.RouterConfig{
		Lookup: func(deviceID string) (ingest.DeviceInfo, bool) {
			if registry == nil {
				return ingest.DeviceInfo{}, false
			}
			dev, ok := registry.Get(deviceID)
			if !ok {
				return ingest.DeviceInfo{}, false
			}
			tenant, err := uuid.Parse(dev.TenantID())
			if err != nil {
				return ingest.DeviceInfo{}, false
			}
			id := dev.Identity()
			return ingest.DeviceInfo{
				TenantID: tenant,
				Own:      domain.Address{LID: id.LID, PN: id.PN},
			}, true
		},
		Keys:     a.keys,
		KeyStore: a.keys,
		Messages: a.messages,
		Receipts: a.receipts,
		Contacts: a.contacts,
		Unread:   a.unread,
		Groups:   a.groups,
		Bus:      a.bus,
		Media:    a.worker,
		Retries:  a.retrier,
		Metrics:  a.metrics,
		// The join whatsmeow has been writing all along: group participants are
		// addressed by LID, contacts are keyed by phone number, and without this
		// a group sender matches no contact and shows up with no name.
		Phones: wa.NewLIDMap(container),
		Log:    lg,
	})
	if err != nil {
		closeAll()
		return nil, nil, err
	}

	registry, err = wa.NewRegistry(wa.RegistryConfig{
		Container: container,
		Store:     a.devices,
		Sink:      router,
		Locker:    pg.NewLocker(pools.API),
		Log:       lg,
		WireLog:   cfg.Log.Wire,
		OnStatus: func(tenantID, deviceID string, status wa.Status, reason string) {
			if ws != nil {
				ws.BroadcastDeviceStatus(tenantID, deviceID, string(status), reason)
			}
		},
	})
	if err != nil {
		closeAll()
		return nil, nil, err
	}
	closers = append(closers, func() {
		// Detached from ctx rather than derived from it: teardown runs
		// precisely because ctx was cancelled, and a dead context would make
		// StopAll return before disconnecting anything.
		stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		registry.StopAll(stopCtx)
	})

	// Built after the router because it seals through it: the router is what
	// holds a tenant's sealer, and a second one here would be a second place
	// that could be given the wrong key. And before the websocket server,
	// which nudges it when a reader meets a face it cannot draw.
	a.avatars, err = media.NewAvatarWorker(media.AvatarConfig{
		Contacts: a.contacts,
		Devices:  a.devices,
		Tenants:  a.activeTenants,
		Clients: func(_ context.Context, _ uuid.UUID, deviceID string) (media.AvatarClient, error) {
			dev, running := registry.Get(deviceID)
			if !running {
				return nil, errors.New("that device is not connected right now")
			}
			return dev.Client(), nil
		},
		Sealer: router,
		Log:    lg,
	})
	if err != nil {
		closeAll()
		return nil, nil, err
	}

	ws = wsapi.NewServer(wsapi.Config{
		Keys: a.apiKeys, Sessions: store.NewUsers(a.pools.API),
		Accounts: store.NewUsers(a.pools.API),
		Devices:  a.devices, Messages: a.messages, Keys2: a.keys,
		Receipts: a.receipts, Unread: a.unread,
		Retrier: a.retrier, Media: a.media, Contacts: a.contacts,
		Avatars:  a.avatars,
		Groups:   a.groups,
		Registry: registry, Bus: a.bus, Router: router, Metrics: a.metrics,
		Blob: a.blob, Pool: pools.API,
		Limits: a.limits, Log: lg,
	})

	a.registry, a.router, a.ws = registry, router, ws
	return a, closeAll, nil
}

func serve() error {
	// SIGINT and SIGTERM cancel the root context, unwinding everything below.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a, closeAll, err := setup(ctx, true)
	if err != nil {
		return err
	}
	defer closeAll()
	a.log.Info("starting", "config", a.cfg.String())
	if !a.cfg.Storage.Configured {
		a.log.Warn("object storage is not configured; media features will be unavailable " +
			"(set WS_S3_BUCKET, WS_S3_ACCESS_KEY and WS_S3_SECRET_KEY when you need them)")
	}

	// The browser client is optional. Serving the API without it is a fine
	// deployment, so a missing build is reported once here rather than
	// answering every request with an unexplained 404.
	web, err := webui.New(a.cfg.Web.Dir, a.log)
	switch {
	case err == nil:
		a.web = web
		a.log.Info("serving the web client", "dir", web.Dir())
	case errors.Is(err, webui.ErrNotBuilt):
		a.log.Info("no web client built; serving the api only",
			"dir", a.cfg.Web.Dir, "build_with", "cd web && npm install && npm run build")
	default:
		return err
	}

	// Before serving: a device that is reachable but unsupervised is worse
	// than one that is plainly down, because everything reports healthy while
	// messages quietly stop arriving.
	if err := a.resumeDevices(ctx); err != nil {
		return err
	}

	// And keep trying. One attempt at boot is one too few: a restart overlaps
	// with the process it replaces, the new one loses the race for the device
	// lock, and without this it never asks again — leaving a device that
	// reports online while nothing holds its connection.
	go a.superviseDevices(ctx)

	// The attachment queue lives in the database, so this starts whether or
	// not anything is waiting and picks up whatever a previous process left.
	go a.worker.Run(ctx)

	// History sync chunks are ingested off the device's event goroutine.
	// whatsmeow dispatches synchronously, so doing it inline would stop a
	// device receiving anything at all for the length of a bootstrap.
	go a.router.RunHistory(ctx)

	// Names whatsmeow already has, moved somewhere sealed. Runs before the
	// avatar worker so the pictures land on rows that mean something.
	a.importContacts(ctx)
	a.syncGroups(ctx)
	a.seedGroupIdentities(ctx)

	// Profile pictures. Paced on purpose: each question is a query over the
	// same socket that carries messages.
	go a.avatars.Run(ctx)

	// Retention windows and housekeeping, once an hour. Nothing here runs
	// for a tenant that has not asked for it.
	go a.maintain(ctx)

	// Chats that predate the identity column get one now. Doing it here rather
	// than in SQL keeps a single implementation of the derivation: a mismatch
	// between a Go version and a SQL version would be silent, and would only
	// surface as names that refuse to open.
	// Names before pictures: a group sender addressed by LID matches no contact
	// until this runs, and everything downstream shows them as a stranger.
	if err := a.linkPhoneNumbers(ctx); err != nil {
		return err
	}

	if err := a.backfillChatIdentities(ctx); err != nil {
		return err
	}

	srv := &http.Server{
		Addr:    a.cfg.HTTPAddr,
		Handler: a.routes(),
		// No ReadTimeout or WriteTimeout on purpose: this process carries
		// long-lived websocket sessions and a write deadline would sever them
		// mid-stream. ReadHeaderTimeout still covers slowloris, which is what
		// a blanket ReadTimeout is usually reached for.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       5 * time.Minute,
		BaseContext:       func(net.Listener) context.Context { return obs.WithLogger(ctx, a.log) },
	}

	errc := make(chan error, 1)
	ln, err := listenPatiently(ctx, a.cfg.HTTPAddr, a.log)
	if err != nil {
		return err
	}

	var probesSrv *http.Server
	if a.cfg.MetricsAddr != "" {
		mux := http.NewServeMux()
		a.probes(mux)
		probesSrv = &http.Server{Addr: a.cfg.MetricsAddr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		pln, err := listenPatiently(ctx, a.cfg.MetricsAddr, a.log)
		if err != nil {
			return err
		}
		go func() {
			a.log.Info("metrics and probes listening", "addr", a.cfg.MetricsAddr)
			if err := probesSrv.Serve(pln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}()
	}

	go func() {
		a.log.Info("http listening", "addr", a.cfg.HTTPAddr)
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()

	select {
	case err := <-errc:
		return fmt.Errorf("http: %w", err)
	case <-ctx.Done():
		a.log.Info("shutting down")
	}

	// Both at once, because a restart is waiting on both and they are
	// independent.
	//
	// The two things a replacement process needs are the TCP port and the
	// devices' advisory locks, and each used to be held hostage by the other.
	// Draining HTTP first meant the locks stayed taken across the drain;
	// stopping devices first meant the port stayed bound while every WhatsApp
	// socket was closed politely. Neither ordering is right, because there is
	// no reason to order them at all.
	//
	// Own contexts, not the root one: it is already cancelled, and a cancelled
	// context makes Shutdown abandon in-flight requests immediately.
	teardown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var shutdownErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		// Closes the listener first thing, so the port is free within
		// milliseconds even if connections take longer to finish.
		shutdownErr = srv.Shutdown(teardown)
		if probesSrv != nil {
			if err := probesSrv.Shutdown(teardown); err != nil {
				a.log.Warn("could not stop the metrics listener cleanly", "error", err)
			}
		}
	}()
	go func() {
		defer wg.Done()
		a.registry.StopAll(teardown)
	}()
	wg.Wait()

	if shutdownErr != nil {
		a.log.Error("graceful shutdown timed out", "error", shutdownErr)
		return shutdownErr
	}
	a.log.Info("stopped")
	return nil
}

// listenPatiently binds the port, waiting out a process that is still letting
// go of it.
//
// `kill $pid && ./bin/whatserverd` is what anybody types, and it races: the old
// process needs a moment to close its listener, and the new one arrives during
// it. Failing there kills the replacement and leaves nothing running at all,
// which is exactly what happened on this installation -- the operator issued a
// restart and ended up with a server that was simply gone.
//
// So it asks again for a few seconds, the same way the device supervisor does,
// and says out loud that it is waiting. A port genuinely held by something else
// still fails, just with an error that names the likely cause.
func listenPatiently(ctx context.Context, addr string, log *slog.Logger) (net.Listener, error) {
	const patience = 15 * time.Second
	deadline := time.Now().Add(patience)
	var cfg net.ListenConfig

	for attempt := 0; ; attempt++ {
		ln, err := cfg.Listen(ctx, "tcp", addr)
		if err == nil {
			return ln, nil
		}
		if !errors.Is(err, syscall.EADDRINUSE) || time.Now().After(deadline) {
			return nil, fmt.Errorf("http: listen %s: %w (is another whatserverd "+
				"still running, or still shutting down?)", addr, err)
		}
		if attempt == 0 {
			log.Info("the address is still in use; waiting for it to be released",
				"addr", addr, "patience", patience)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// probes mounts what an orchestrator asks and a scraper reads. On the public
// mux by default; on a listener of its own when WS_METRICS_ADDR is set, so
// the port clients reach carries nothing about the process.
func (a *app) probes(mux *http.ServeMux) {
	// Liveness never touches a dependency, so a database blip cannot get the
	// container killed and restarted straight into the same blip.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		//nolint:errcheck // a failed probe write means the prober hung up
		_, _ = w.Write([]byte("ok\n"))
	})

	// Readiness does check dependencies, so a load balancer stops routing here
	// while Postgres is unreachable.
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if err := a.pools.Ping(ctx); err != nil {
			a.log.Warn("readiness check failed", "error", err)
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		//nolint:errcheck // a failed probe write means the prober hung up
		_, _ = w.Write([]byte("ready\n"))
	})

	mux.Handle("GET /metrics", a.metrics.Handler())
}

func (a *app) routes() http.Handler {
	mux := http.NewServeMux()
	if a.cfg.MetricsAddr == "" {
		a.probes(mux)
	}

	// Signing up and signing in. Over HTTP because the websocket wants
	// credentials before it opens, and this is where credentials come from.
	(&authapi.Handler{
		AccessChanged: a.ws.RevalidateAccess,
		Users:         store.NewUsers(a.pools.API), Keys: a.keys,
		Devices: a.devices, Limits: a.limits, Log: a.log,
	}).Mount(mux)

	mux.Handle("/v1/ws", a.ws)

	// Attachments go over HTTP rather than through the websocket. A two
	// hundred megabyte video framed down the same connection as live messages
	// would stall every other frame behind it and would sit in memory on both
	// ends; here it streams, resumes and caches like any other file. What it
	// streams is ciphertext.
	mux.Handle("GET /v1/media/{uid}", &media.Handler{
		Keys: a.apiKeys, Sessions: store.NewUsers(a.pools.API),
		Media: a.media, Blob: a.blob, Log: a.log,
	})
	mux.Handle("HEAD /v1/media/{uid}", &media.Handler{
		Keys: a.apiKeys, Sessions: store.NewUsers(a.pools.API),
		Media: a.media, Blob: a.blob, Log: a.log,
	})

	// Sending an attachment is two steps: the bytes come here, and the message
	// that references them goes over the websocket. One step would mean a
	// video framed down the same connection as live messages, stalling
	// everything behind it and sitting in memory on both ends.
	mux.Handle("POST /v1/upload", &media.UploadHandler{
		Keys:     a.apiKeys,
		Sessions: store.NewUsers(a.pools.API),
		Devices:  a.devices,
		Resolve: func(_ context.Context, _ uuid.UUID, deviceID string) (media.Uploader, error) {
			dev, running := a.registry.Get(deviceID)
			if !running {
				return nil, errors.New("it is not connected right now")
			}
			return dev.Client(), nil
		},
		MaxBytes: a.cfg.Storage.MaxMediaBytes,
		Log:      a.log,
	})

	// Last, and only as a catch-all. Go's mux prefers the more specific
	// patterns above, so the client cannot shadow an endpoint.
	if a.web != nil {
		mux.Handle("/", a.web)
	}
	return mux
}

// listTenants prints the tenants in this database.
//
// Needed because bootstrap always creates a new tenant, so without a way to see
// what already exists it is easy to end up with several by accident — and then
// wonder why a device paired under one is invisible to a key issued for
// another.
func listTenants() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	a, closeAll, err := setup(ctx, false)
	if err != nil {
		return err
	}
	defer closeAll()

	// tenants and api_keys carry no row-level policy, so they can be read
	// directly. devices does, which is why the count below cannot be a
	// subquery here: without app.tenant_id set the policy hides every row and
	// the count silently comes back zero.
	//
	// Counting per tenant inside a scoped transaction is one query per tenant
	// rather than one overall. For an admin command over a handful of tenants
	// that is the right trade: the alternative is a role with BYPASSRLS, and
	// introducing one of those to make a status listing prettier would put a
	// permanent hole in the isolation model.
	type row struct {
		id, name string
		created  time.Time
		keys     int
	}
	var tenants []row

	rows, err := a.pools.API.Query(ctx, `
		SELECT t.id::text, t.name, t.created_at,
		       (SELECT count(*) FROM api_keys k WHERE k.tenant_id = t.id AND k.revoked_at IS NULL)
		  FROM tenants t ORDER BY t.created_at`)
	if err != nil {
		return fmt.Errorf("list tenants: %w", err)
	}
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.name, &r.created, &r.keys); err != nil {
			rows.Close()
			return err
		}
		tenants = append(tenants, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	//nolint:errcheck // writing to stdout; nothing useful to do on failure
	fmt.Fprintln(w, "ID\tNAME\tDEVICES\tONLINE\tKEYS\tCREATED")
	for _, r := range tenants {
		devices, err := a.devices.List(ctx, r.id)
		if err != nil {
			return fmt.Errorf("count devices for %s: %w", r.id, err)
		}
		online := 0
		for _, d := range devices {
			if d.Status == wa.StatusOnline {
				online++
			}
		}
		//nolint:errcheck // writing to stdout
		fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%d\t%s\n", r.id, r.name, len(devices), online, r.keys,
			r.created.Format("2006-01-02 15:04"))
	}
	return w.Flush()
}

// issueKey issues an additional API key for an existing tenant.
func issueKey(args []string) error {
	fs := flag.NewFlagSet("key", flag.ContinueOnError)
	tenant := fs.String("tenant", "", "tenant id (required; see: whatserverd tenants)")
	name := fs.String("name", "cli", "label for this key")
	scopeArg := fs.String("scope", "full",
		"what the key may do: read (the archive as ciphertext), send (plus outbound "+
			"messages), full (plus pairing, stopping devices and backfill)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *tenant == "" {
		fs.Usage()
		return errors.New("key: -tenant is required; run \"whatserverd tenants\" to list them")
	}
	scope, err := store.ParseKeyScope(*scopeArg)
	if err != nil {
		return fmt.Errorf("key: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	a, closeAll, err := setup(ctx, false)
	if err != nil {
		return err
	}
	defer closeAll()

	var exists bool
	if err := a.pools.API.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM tenants WHERE id = $1)`, *tenant).Scan(&exists); err != nil {
		return fmt.Errorf("key: look up tenant: %w", err)
	}
	if !exists {
		return fmt.Errorf("key: no tenant %s; run \"whatserverd tenants\" to list them", *tenant)
	}

	key, err := a.apiKeys.IssueScoped(ctx, *tenant, *name, scope, nil)
	if err != nil {
		return fmt.Errorf("key: %w", err)
	}
	fmt.Printf("api key  %s  (scope %s)\n\nThis key is shown once and cannot be recovered. Store it now.\n", key, scope)
	return nil
}

// bootstrap creates a tenant and prints an API key.
func bootstrap(args []string) error {
	fs := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	name := fs.String("tenant", "", "tenant name (required)")
	keyName := fs.String("key-name", "bootstrap", "label for the issued API key")
	force := fs.Bool("force", false, "create the tenant even if one with this name exists")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		fs.Usage()
		return errors.New("bootstrap: -tenant is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	a, closeAll, err := setup(ctx, false)
	if err != nil {
		return err
	}
	defer closeAll()

	// Names are not unique — two real companies may share one — but creating a
	// second tenant with the same name is almost always a mistake reaching for
	// an API key. The key would work and reach nothing, which is a confusing
	// way to find out.
	var existing int
	if err := a.pools.API.QueryRow(ctx,
		`SELECT count(*) FROM tenants WHERE name = $1`, *name).Scan(&existing); err != nil {
		return fmt.Errorf("bootstrap: check for an existing tenant: %w", err)
	}
	if existing > 0 && !*force {
		return fmt.Errorf("bootstrap: a tenant named %q already exists.\n\n"+
			"If you wanted an API key for it, this is not the command:\n\n"+
			"    ./bin/whatserverd tenants              # find its id\n"+
			"    ./bin/whatserverd key -tenant <ID>     # issue a key for it\n\n"+
			"Pass -force to create a second tenant with the same name anyway", *name)
	}

	var tenantID string
	if err := a.pools.API.QueryRow(ctx,
		`INSERT INTO tenants (name) VALUES ($1) RETURNING id::text`, *name).Scan(&tenantID); err != nil {
		return fmt.Errorf("bootstrap: create tenant: %w", err)
	}
	key, err := a.apiKeys.Issue(ctx, tenantID, *keyName)
	if err != nil {
		return fmt.Errorf("bootstrap: issue api key: %w", err)
	}

	// To stdout, not the logger: this is output, and it is the only time the
	// key exists in readable form. Only its hash is stored.
	fmt.Printf("tenant   %s  (%s)\napi key  %s\n\nThis key is shown once and cannot be recovered. Store it now.\n",
		tenantID, *name, key)
	return nil
}

// listTenantIDs returns every tenant, for commands that are given an identifier
// scoped to a tenant they were not told.
//
// tenants carries no row-level policy, so this one read needs no scoping — and
// every read it enables afterwards still does.
func (a *app) listTenantIDs(ctx context.Context) ([]uuid.UUID, error) {
	rows, err := a.pools.API.Query(ctx, `SELECT id FROM tenants WHERE status = 'active'`)
	if err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// storageBootError turns a failure to reach object storage into something an
// operator can act on without reading the code.
//
// The distinction it draws is the one that was missing: "connection refused"
// and "access denied" both used to surface as `check bucket`, and the first is
// what happens every time Docker has not come up with the machine. It is not a
// configuration error, and telling somebody to check their credentials for it
// wastes their morning. When the endpoint is local the message names the
// command that starts the store, because that is the case where the command
// is known; anywhere else it says what is down and leaves the how to whoever
// runs it.
func storageBootError(err error, cfg config.Storage) error {
	switch {
	case errors.Is(err, blob.ErrUnreachable):
		where := cfg.Endpoint
		if where == "" {
			where = "s3." + cfg.Region + ".amazonaws.com"
		}
		hint := "start it, or leave WS_S3_ENDPOINT unset to boot without attachments " +
			"(they queue in the database until storage appears)"
		if u, perr := url.Parse(cfg.Endpoint); perr == nil && isLocalHost(u.Hostname()) {
			hint = "start it — for the dev compose file that is\n" +
				"  docker compose -f docker-compose.dev.yml up -d minio minio-init\n" +
				"or leave WS_S3_ENDPOINT unset to boot without attachments " +
				"(they queue in the database until storage appears)"
		}
		return fmt.Errorf("object storage at %s is not reachable: %w\n%s", where, err, hint)
	case errors.Is(err, blob.ErrRefused):
		return fmt.Errorf("object storage refused the credentials in WS_S3_ACCESS_KEY / "+
			"WS_S3_SECRET_KEY for bucket %q: %w", cfg.Bucket, err)
	}
	return err
}

// isLocalHost says whether a host name is this machine.
func isLocalHost(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1", "[::1]":
		return true
	}
	return false
}
