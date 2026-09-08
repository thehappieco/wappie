package seal

import "time"

// SetClockForTest replaces a sealer's clock, so age-based rotation can be
// tested without waiting fifteen minutes. Test-only: defined in a _test file
// so it is not part of the package's API.
func SetClockForTest(s *Sealer, now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
}
