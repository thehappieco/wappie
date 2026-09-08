-- How many people a message was sent to.
--
-- Ticks need a denominator. "Everyone received it" is not a fact about the
-- receipts alone: two acknowledgements mean everything in a conversation
-- between two people and almost nothing in a group of forty, and a client with
-- no denominator can only ever draw one grey tick and hope.
--
-- The count rather than the list, deliberately, and only for now. The list —
-- who is in the group, who is an admin, who removed whom and when — is a table
-- of its own with a history behind it, and it belongs to the phase that builds
-- the group panel. Storing a number here buys the ticks their denominator
-- without pretending to that, and the column keeps its meaning when the list
-- arrives beside it.
--
-- Null for a direct conversation, where the answer is one and needs no column,
-- and for any group WhatsApp has not been asked about yet. A tick that does not
-- know its denominator must not be promoted past one grey — saying "everyone"
-- on the strength of a number nobody has is the failure this column exists to
-- prevent, not one it can be allowed to cause.
ALTER TABLE chats ADD COLUMN participant_count integer;

COMMENT ON COLUMN chats.participant_count IS
    'Members of the group, per WhatsApp, including us. The denominator behind '
    '"everyone received it". Null means unknown, and a tick must not be '
    'promoted on an unknown denominator.';
