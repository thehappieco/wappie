package wsapi

// SetSubscribeHook installs a hook at the subscribe's seams ("granted",
// "page"), so a test can commit a deletion exactly between two of them.
func SetSubscribeHook(cfg *Config, hook func(stage string)) { cfg.subscribeHook = hook }
