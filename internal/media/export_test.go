package media

// SetStreamHook sets the seam a token's download runs before its first
// chunk.
func SetStreamHook(h *Handler, hook func(stage string)) { h.streamHook = hook }
