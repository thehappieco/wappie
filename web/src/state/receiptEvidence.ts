import type { ReaderRevisionView } from './archive'

function valid(date: Date | undefined): Date | undefined {
  return date && Number.isFinite(date.getTime()) ? date : undefined
}

/** A timestamp without explicit evidence must not become a read indicator. */
export function receiptEvidence(revision: ReaderRevisionView | undefined) {
  return {
    delivered: valid(revision?.delivered),
    read: revision?.confirmed === true ? valid(revision.read) : undefined,
    played: revision?.playedConfirmed === true ? valid(revision.played) : undefined,
  }
}
