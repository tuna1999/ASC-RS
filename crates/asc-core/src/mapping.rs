//! R8 / ProGuard `mapping.txt` reader (ASC-RS-GUI-008).
//!
//! The file is line oriented:
//!
//! ```text
//! com.example.Secret -> a.b:
//!     int balance -> a
//!     12:34:void charge(int) -> a
//! ```
//!
//! Class lines end in `:` and are unindented; their member lines are
//! indented and only the member name plus the target name matter here.
//! Anything unparsable is skipped, never fatal: the mapping is a
//! convenience for reading an obfuscated build, not load-bearing data.

/// One resolved mapping entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingHit {
    /// Original (unobfuscated) class name.
    pub original_class: String,
    /// Original member name, empty for a class-level hit.
    pub original_member: String,
    /// Obfuscated class that replaced it.
    pub mapped_class: String,
    /// Obfuscated member name, empty for a class-level hit.
    pub mapped_member: String,
}

/// Parsed mapping file.
#[derive(Debug, Default)]
pub struct MappingIndex {
    classes: Vec<(String, String)>,
    members: Vec<(String, String, String, String)>,
}

impl MappingIndex {
    /// Parse `text`; never fails.
    pub fn parse(text: &str) -> Self {
        let mut index = Self::default();
        let mut current: Option<(String, String)> = None;
        for line in text.lines() {
            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                continue;
            }
            let indented = line.starts_with(' ') || line.starts_with('\t');
            if !indented {
                if let Some((from, to)) = halves(line.trim_end_matches(':')) {
                    current = Some((from.to_string(), to.to_string()));
                    index.classes.push((from, to));
                } else {
                    current = None;
                }
                continue;
            }
            let Some((from_class, to_class)) = current.clone() else {
                continue;
            };
            // Member lines may carry a line-number prefix and signature:
            // `<…>name[:desc][:ret] -> target`. The name is the last
            // segment before `:` or the whole word.
            let Some((left, right)) = halves(line.trim()) else {
                continue;
            };
            let name = left
                .rsplit_once([' ', ':'])
                .map_or(left.as_str(), |(_, n)| n);
            // `name(int)` / `name:desc` — keep the bare name.
            let name = name.split(['(', ':']).next().unwrap_or(name);
            index
                .members
                .push((from_class, name.to_string(), to_class, right));
        }
        index
    }

    /// Entries whose original class or member contains `needle`
    /// (case-insensitive). Classes come first, then members, both in
    /// file order.
    pub fn lookup(&self, needle: &str) -> Vec<MappingHit> {
        let needle = needle.trim();
        if needle.is_empty() {
            return Vec::new();
        }
        let needle = needle.to_ascii_lowercase();
        let mut hits: Vec<MappingHit> = self
            .classes
            .iter()
            .filter(|(from, to)| {
                from.to_ascii_lowercase().contains(&needle)
                    || to.to_ascii_lowercase().contains(&needle)
            })
            .map(|(from, to)| MappingHit {
                original_class: from.clone(),
                original_member: String::new(),
                mapped_class: to.clone(),
                mapped_member: String::new(),
            })
            .collect();
        hits.extend(
            self.members
                .iter()
                .filter(|(from, name, to_class, to_name)| {
                    // Both sides answer: the original name and the
                    // obfuscated one you actually read in the code.
                    name.to_ascii_lowercase().contains(&needle)
                        || from.to_ascii_lowercase().contains(&needle)
                        || to_name.to_ascii_lowercase().contains(&needle)
                        || to_class.to_ascii_lowercase().contains(&needle)
                })
                .map(|(from, name, to_class, to_name)| MappingHit {
                    original_class: from.clone(),
                    original_member: name.clone(),
                    mapped_class: to_class.clone(),
                    mapped_member: to_name.clone(),
                }),
        );
        hits
    }

    /// Parsed entry counts (classes, members).
    pub fn counts(&self) -> (usize, usize) {
        (self.classes.len(), self.members.len())
    }

    pub fn is_empty(&self) -> bool {
        self.classes.is_empty() && self.members.is_empty()
    }
}

/// Split `left -> right`, trimming both halves.
fn halves(line: &str) -> Option<(String, String)> {
    let (left, right) = line.split_once("->")?;
    let left = left.trim();
    let right = right.trim();
    (!left.is_empty() && !right.is_empty()).then(|| (left.to_string(), right.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
# compiler: R8
com.example.Secret -> a.b:
    int balance -> a
    12:34:void charge(int) -> b
com.example.Other -> a.c:
    void run() -> a
";

    #[test]
    fn lookup_finds_the_obfuscated_side_too() {
        let index = MappingIndex::parse("com.example.Real -> a:\n    void realMethod() -> b\n");
        assert!(
            index.lookup("a").iter().any(|h| h.mapped_class == "a"),
            "the mapped class answers"
        );
        assert!(
            index.lookup("b").iter().any(|h| h.mapped_member == "b"),
            "the mapped member answers"
        );
        assert!(
            index
                .lookup("Real")
                .iter()
                .any(|h| h.original_class.contains("Real")),
            "the original still answers"
        );
    }

    #[test]
    fn classes_and_members_are_indexed() {
        let index = MappingIndex::parse(SAMPLE);
        assert_eq!(index.counts(), (2, 3));
        let hits = index.lookup("secret");
        assert_eq!(hits[0].mapped_class, "a.b", "class hit first");
        assert!(hits.iter().any(|h| h.original_member == "balance"
            && h.mapped_member == "a"
            && h.mapped_class == "a.b"));
    }

    #[test]
    fn members_are_found_by_their_own_name() {
        let index = MappingIndex::parse(SAMPLE);
        let hits = index.lookup("charge");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].mapped_member, "b");
        assert_eq!(hits[0].original_class, "com.example.Secret");
    }

    #[test]
    fn a_member_belongs_to_the_preceding_class_only() {
        let index = MappingIndex::parse(SAMPLE);
        let other = index
            .lookup("run")
            .into_iter()
            .find(|h| h.original_member == "run")
            .expect("run is mapped");
        assert_eq!(other.mapped_class, "a.c");
        assert!(
            !index
                .lookup("balance")
                .iter()
                .any(|h| h.mapped_class == "a.c")
        );
    }

    #[test]
    fn garbage_and_empty_input_are_survivable() {
        assert!(MappingIndex::parse("").is_empty());
        assert!(
            MappingIndex::parse("not a mapping\n    orphan -> x")
                .lookup("orphan")
                .is_empty()
        );
        assert!(MappingIndex::parse("a -> b:").lookup("   ").is_empty());
    }
}
