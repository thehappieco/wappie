package send

import (
	"errors"
	"fmt"
	"mime"
	"strings"

	"whatserver2/internal/domain"
)

// ErrInvalidVideo describes a request that cannot produce the selected video
// format. It is a caller error, not a transient send failure.
var ErrInvalidVideo = errors.New("send: invalid video")

// ValidateVideo checks declared metadata without decoding the uploaded bytes.
// Older API clients may omit duration; the browser always measures its video.
func ValidateVideo(a Attachment) error {
	if a.Type != domain.TypeVideo && a.Type != domain.TypePTV {
		return nil
	}
	mediaType, _, err := mime.ParseMediaType(a.MimeType)
	if err != nil || !strings.HasPrefix(mediaType, "video/") {
		return fmt.Errorf("%w: a video needs its actual video MIME type", ErrInvalidVideo)
	}
	if a.Type != domain.TypePTV {
		return nil
	}
	if a.Caption != "" {
		return fmt.Errorf("%w: a round video note carries no caption", ErrInvalidVideo)
	}
	if a.IsGIF {
		return fmt.Errorf("%w: a round video note cannot also be a looping GIF", ErrInvalidVideo)
	}
	if a.Seconds > 60 {
		return fmt.Errorf("%w: a round video note is limited to 60 seconds; send a normal video instead", ErrInvalidVideo)
	}
	return nil
}
