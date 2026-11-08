package media

// SetStreamHook sets the seams a token's download runs before its first
// chunk ("streaming") and when its monitor cuts it ("cut").
func SetStreamHook(h *Handler, hook func(stage string)) { h.streamHook = hook }
