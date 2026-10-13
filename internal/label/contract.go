// Package label names a number to people who may no longer see it: the
// snapshot a notice and an event row keep of a deleted number, so they can
// say which one it was after the number itself is gone (decision 0038).
//
// Nothing here ever reads a LID, and nothing here returns a phone number.
package label

import "strings"

// HintFromPN is "…" and the last four digits of the user part of a stored
// phone-number JID ("5511912345678:12@s.whatsapp.net" gives "…5678"), or nil
// when fewer than four digits are left. The rest of the number never leaves
// it, and a LID-only number has no hint at all.
func HintFromPN(pn string) *string {
	user, _, _ := strings.Cut(pn, "@")
	user, _, _ = strings.Cut(user, ":")
	var digits []byte
	for i := 0; i < len(user); i++ {
		if c := user[i]; c >= '0' && c <= '9' {
			digits = append(digits, c)
		}
	}
	if len(digits) < 4 {
		return nil
	}
	hint := "…" + string(digits[len(digits)-4:])
	return &hint
}
