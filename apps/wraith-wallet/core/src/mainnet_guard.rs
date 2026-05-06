//! Mainnet-readiness guards.
//!
//! Lightweight rules that run only when the wallet is configured for
//! `Network::Bitcoin` (real bitcoin) and are no-ops on signet / testnet /
//! regtest. The principle: gates here cost almost nothing on the happy
//! path but stop the obvious foot-guns that turn into permanent loss on
//! mainnet.
//!
//! Currently:
//!   - [`is_known_weak_mnemonic`]: refuses canonical BIP-39 test vectors
//!     and other widely-published mnemonics whose addresses have been
//!     swept thousands of times. Anyone importing one on mainnet would
//!     watch their funds disappear within blocks.
//!
//! What this module deliberately does NOT do:
//!   - Block "low-entropy looking" mnemonics. The space is unbounded and
//!     any heuristic will either let bad seeds through or refuse good
//!     ones. We block exact matches against a curated list, nothing more.
//!   - Run any check unless `network == Network::Bitcoin`. Test networks
//!     are explicitly the place to use test vectors.

/// Curated list of mnemonics that are known to be public, included in
/// docs / test suites / tutorial videos / debug logs. Importing any of
/// these on mainnet means an attacker who's already memorised them will
/// sweep the funds before the first confirmation.
///
/// Mnemonic comparison is whitespace-normalised (any run of whitespace
/// counts as one separator) and case-sensitive. BIP-39 wordlist entries
/// are all lowercase by spec, so case-sensitive is the correct policy:
/// a mnemonic with capitalised words isn't valid BIP-39 and should fail
/// at the parse layer regardless.
const KNOWN_WEAK_MNEMONICS: &[&str] = &[
    // The canonical 12-word BIP-39 test vector. By far the most common
    // foot-gun: it's literally the first example in the BIP-39 doc and
    // shows up in nearly every wallet's test suite.
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    // The canonical 24-word BIP-39 test vector.
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
    // Trezor's 24-word test vector, widely used in Trezor / KeepKey docs.
    "panda eyebrow bullet gorilla call smoke muffin taste mesh discover \
     soft ostrich alcohol speed nation flash devote level hobby quick \
     inner drive ghost inside",
    // Common "all" / "zoo" 12-word patterns that surface in tutorials.
    "all all all all all all all all all all all all",
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo",
    // legacy bitcoin "letter" demo that pops up in old YouTube tutorials.
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
];

/// Returns `true` if `mnemonic` matches any entry in [`KNOWN_WEAK_MNEMONICS`]
/// after whitespace normalisation. The intended use is:
///
/// ```ignore
/// if network == Network::Bitcoin && is_known_weak_mnemonic(&words) {
///     return Err("won't import a publicly-known mnemonic on mainnet".into());
/// }
/// ```
///
/// The match is exact (after collapsing whitespace) — this is not a
/// similarity check and won't catch novel weak seeds. Its only job is to
/// stop the well-known examples from going to production.
pub fn is_known_weak_mnemonic(mnemonic: &str) -> bool {
    let normalised = normalise_words(mnemonic);
    KNOWN_WEAK_MNEMONICS
        .iter()
        .any(|known| normalise_words(known) == normalised)
}

fn normalise_words(s: &str) -> String {
    s.split_whitespace().collect::<Vec<&str>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_abandon_vector_is_blocked() {
        assert!(is_known_weak_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon about"
        ));
    }

    #[test]
    fn whitespace_variants_are_normalised() {
        // Tabs, double spaces, leading/trailing whitespace all collapse.
        assert!(is_known_weak_mnemonic(
            "  abandon abandon abandon abandon abandon abandon\tabandon abandon \
              abandon abandon abandon  about  "
        ));
    }

    #[test]
    fn random_strong_mnemonic_passes() {
        // Generated via `bip39 generate -w 12` — not in the public list.
        assert!(!is_known_weak_mnemonic(
            "violin liquid drama choose surge coyote fortune exclude tongue \
             scrap virus narrow"
        ));
    }

    #[test]
    fn similar_but_different_mnemonic_passes() {
        // Differs from the canonical vector by one word.
        assert!(!is_known_weak_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon zoo"
        ));
    }

    #[test]
    fn known_weak_list_has_at_least_one_24_word_entry() {
        // Sanity: don't accidentally drop the 24-word coverage on a
        // future cleanup pass.
        assert!(KNOWN_WEAK_MNEMONICS
            .iter()
            .any(|m| m.split_whitespace().count() == 24));
    }
}
