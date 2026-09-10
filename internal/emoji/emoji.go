// Package emoji validates one complete emoji, including multi-code-point
// sequences, using the same pinned Unicode catalogue as the browser.
package emoji

import (
	_ "embed"
	"encoding/json"
)

//go:embed emoji.json
var catalogue []byte

var accepted = func() map[string]string {
	var data struct {
		Groups []struct {
			Emojis [][]string `json:"emojis"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(catalogue, &data); err != nil {
		panic("invalid embedded emoji catalogue: " + err.Error())
	}
	result := map[string]string{"": ""}
	for _, group := range data.Groups {
		for _, variants := range group.Emojis {
			for _, value := range variants {
				result[value] = variants[0]
			}
		}
	}
	return result
}()

// Normalize accepts a complete Unicode 17 emoji or the empty withdrawal.
// Presentation aliases map to the fully-qualified sequence. Standalone tone
// modifiers, arbitrary ZWJ chains, text and multiple emoji are not reactions.
func Normalize(value string) (string, bool) {
	if len(value) > 128 {
		return "", false
	}
	canonical, ok := accepted[value]
	return canonical, ok
}
