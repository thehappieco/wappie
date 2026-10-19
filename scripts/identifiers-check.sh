#!/bin/sh
# identifiers-check.sh [<rev>...]: fails if the repository names the id of a
# real AWS account in a tracked file of the commits given (the checked-out
# commit by default; git rev-list syntax, so origin/main..HEAD checks every
# commit a push would publish), in a path of one, or in one of their commit
# messages. The account's ARNs belong in the release artifacts, which name
# them by design (docs/mcp-enclave.md section 9), never in the source.
#
# The history before this check names the owner's account (from 7bff856,
# 2026-09-25, until the commit before this check) and is not rewritten, so
# unlike the kit's check (github.com/thehappieco/kit,
# scripts/identifiers-check.sh), which this one follows, the default is the
# checked-out commit, not its whole history. Anything pushed is public: run
# it over origin/main..HEAD before pushing.
#
# Two checks, each over the files, the paths and the commit messages of
# every commit given, and this file names no real value in either:
#
#  1. An AWS account id in an ARN or in an account-id field, whatever its
#     value: only AWS's documentation placeholders are allowed.
#  2. The owner's private list: one string per line (the account id, and
#     anything else of the account never to publish), matched as a fixed
#     string without regard to case, from $WAPPIE_IDENTIFIERS (in CI, the
#     repository secret of that name) or else from identifiers.local.txt at
#     the repository's root (git-ignored, *.local.*). The list never goes
#     into the repository: a public rule would have to spell the values it
#     forbids. With CI=true and no list, the check fails.
#
# A match is reported by commit, place and the check that matched, never by
# what matched: a file by its path and line, a commit message by its line,
# and a path that matches a class or the list, or a file whose path does, by
# its index in the commit's tree (line N of git ls-tree -r --name-only
# <commit>), so the value never reaches a log through its file's name. Run
# by make identifiers-check, which CI runs.
set -eu

[ $# -gt 0 ] || set -- --no-walk HEAD
cd "$(git rev-parse --show-toplevel)"
revs=$(git rev-list "$@")
[ -n "$revs" ] || { echo "identifiers-check: no commit in $*"; exit 1; }
count=$(printf '%s\n' "$revs" | wc -l | tr -d ' ')

list=$(mktemp)
found=$(mktemp)
hits=$(mktemp)
texthits=$(mktemp)
message=$(mktemp)
paths=$(mktemp)
trap 'rm -f "$list" "$found" "$hits" "$texthits" "$message" "$paths"' EXIT

# grep_revs <git grep options>...: git grep over every commit, into $hits.
# Exit status 1 is no match; anything else but 0 is an error, which fails
# the check rather than pass it unread.
grep_revs() {
	rc=0
	# shellcheck disable=SC2086 # one commit per word
	git grep "$@" $revs > "$hits" || rc=$?
	[ "$rc" -le 1 ] || { echo "identifiers-check: git grep failed ($rc)"; exit 1; }
}

# grep_text <file> <grep options>...: grep -n of a text, into $texthits,
# with the same rule for the exit status.
grep_text() {
	f=$1
	shift
	rc=0
	grep -n "$@" "$f" > "$texthits" || rc=$?
	[ "$rc" -le 1 ] || { echo "identifiers-check: grep failed ($rc)"; exit 1; }
}

# One value per line; carriage returns, surrounding blanks and blank lines
# go, so a list pasted into the secret's form matches as written.
clean() { tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | grep -v '^$' || true; }
if [ -n "${WAPPIE_IDENTIFIERS:-}" ]; then
	printf '%s\n' "$WAPPIE_IDENTIFIERS" | clean > "$list"
elif [ -f identifiers.local.txt ]; then
	clean < identifiers.local.txt > "$list"
fi
if [ ! -s "$list" ]; then
	if [ "${CI:-}" = true ]; then
		echo "identifiers-check: no private list: the repository secret WAPPIE_IDENTIFIERS is empty or not passed to this job"
		exit 1
	fi
	echo "identifiers-check: no private list (WAPPIE_IDENTIFIERS or identifiers.local.txt), so the classes only"
fi

# The only account ids a class may hold: AWS's documentation placeholders.
accounts='^(123456789012|111122223333|444455556666|777788889999)$'

field='["'\'']?[[:space:]]*[:=][[:space:]]*["'\'']?'

# classes <command> [<argument>...]: runs the command once per class, with
# the class's <name> <pattern> <value> <allowed> after its own arguments:
# every match of the extended regular expression <pattern>, reduced to the
# first match of <value> in it, must match <allowed>.
classes() {
	"$@" 'an AWS account id in an ARN' 'arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:[0-9]{12}:' '[0-9]{12}:$' "$(printf '%s' "$accounts" | sed 's/)\$$/):$/')"
	"$@" 'an AWS account id in a field' "([Aa]ccount_?[Ii][Dd]|AWS_ACCOUNT_ID|AWSAccountId)${field}[0-9]{10,13}" '[0-9]{10,13}$' "$accounts"
}

# allowed <match> <value> <allowed>: whether the first match of <value> in
# <match> is one of the values <allowed> holds.
allowed() {
	value=$(printf '%s\n' "$1" | grep -o -E -e "$2" | head -n 1) || value=
	printf '%s\n' "$value" | grep -q -i -E -e "$3"
}

# A path that matches any class's pattern, whatever its value, or the list
# is never printed: it is shown by its index in its commit's tree.
any_class=
add_pattern() { any_class="${any_class:+$any_class|}($2)"; }
classes add_pattern
named() {
	if [ -s "$list" ] && printf '%s\n' "$1" | grep -q -i -F -f "$list"; then
		return 0
	fi
	printf '%s\n' "$1" | grep -q -E -e "$any_class"
}
# shown <rev> <path>: the path as a report prints it.
shown() {
	if named "$2"; then
		n=$(git ls-tree -r --name-only "$1" | grep -n -x -F -e "$2" | head -n 1 | cut -d: -f1) || n=
		echo "path #${n:-?} of its tree"
	else
		printf '%s\n' "$2"
	fi
}

# in_files <name> <pattern> <value> <allowed>: the class in every text file
# of every commit.
in_files() {
	grep_revs -I -n -o -E -e "$2"
	while IFS= read -r hit; do
		rev=${hit%%:*}
		rest=${hit#*:}
		path=${rest%%:*}
		rest=${rest#*:}
		line=${rest%%:*}
		match=${rest#*:}
		if ! allowed "$match" "$3" "$4"; then
			echo "$(echo "$rev" | cut -c1-12) $(shown "$rev" "$path"):$line: $1" >> "$found"
		fi
	done < "$hits"
}

# in_text <text> <place> <commit> <name> <pattern> <value> <allowed>: the
# class in a commit's message or in its list of paths, one per line; a match
# is reported by its line number, put into the printf format <place>.
in_text() {
	grep_text "$1" -o -E -e "$5"
	while IFS= read -r hit; do
		if ! allowed "${hit#*:}" "$6" "$7"; then
			# shellcheck disable=SC2059 # the format is this file's
			printf "$3 $2: $4\n" "${hit%%:*}" >> "$found"
		fi
	done < "$texthits"
}

classes in_files

if [ -s "$list" ]; then
	grep_revs --text -n -i -F -f "$list"
	while IFS= read -r hit; do
		rev=${hit%%:*}
		rest=${hit#*:}
		path=${rest%%:*}
		rest=${rest#*:}
		line=${rest%%:*}
		echo "$(echo "$rev" | cut -c1-12) $(shown "$rev" "$path"):$line: an identifier of the private list" >> "$found"
	done < "$hits"
fi

for rev in $revs; do
	short=$(echo "$rev" | cut -c1-12)
	git log -1 --format=%B "$rev" > "$message"
	git ls-tree -r --name-only "$rev" > "$paths"
	classes in_text "$message" 'commit message, line %s' "$short"
	classes in_text "$paths" 'path #%s of its tree' "$short"
	if [ -s "$list" ]; then
		grep_text "$message" -i -F -f "$list"
		cut -d: -f1 "$texthits" | while IFS= read -r n; do
			echo "$short commit message, line $n: an identifier of the private list"
		done >> "$found"
		grep_text "$paths" -i -F -f "$list"
		cut -d: -f1 "$texthits" | while IFS= read -r n; do
			echo "$short path #$n of its tree: an identifier of the private list"
		done >> "$found"
	fi
done

if [ -s "$found" ]; then
	sort -u "$found"
	echo "identifiers-check: $(sort -u "$found" | wc -l | tr -d ' ') matches in $count commits (path #N is line N of git ls-tree -r --name-only <commit>)"
	exit 1
fi
echo "identifiers-check: $count commits, their files, paths and messages, no identifier of an AWS account"
