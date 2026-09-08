-- Say WHAT an unsupported message was.
--
-- A message this build cannot classify is stored with type='unsupported' and
-- nothing else. Since the payload is sealed, that is a dead end: nobody can
-- find out which waE2E branch to implement next without guessing, and on the
-- installation where this was written 26% of live traffic was landing there.
--
-- The value is a protobuf field name -- "albumMessage", "pollCreationMessageV3"
-- -- taken from the compiled descriptor, so the vocabulary is bounded by this
-- binary rather than by the sender. That is the same class of disclosure as the
-- type column beside it, which already holds waE2E field names translated:
-- 'image' IS imageMessage, 'ptt' IS audioMessage with the PTT flag. Sealing it
-- would not protect the reader -- the client holds the key and can parse the
-- raw protobuf anyway -- it would only blind the operator who has to decide
-- what to build.
ALTER TABLE messages ADD COLUMN unsupported_field text;

COMMENT ON COLUMN messages.unsupported_field IS
    'Protobuf field name for type=unsupported rows. Unsealed: it names the '
    'kind of thing, exactly as the type column does, from a vocabulary fixed '
    'by the compiled schema.';
