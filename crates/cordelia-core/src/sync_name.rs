//! The one spelling of a name a folder syncs under.
//!
//! A name is written in three places: typed at the command line, sent to
//! the node in a list of exclusions, and found from a git remote. All
//! three tidy it with [`tidy`], so a name written in one is the name read
//! in another: a project's name typed as an exclusion is the name that
//! project is found under.

/// `name` with one spelling: lower case, with nothing around it, and with
/// no `.git` and no `/` at its end, however that was typed (`Repo.GIT`,
/// `owner/repo.git/`).
///
/// Tidying a tidy name changes nothing, so it does not matter how many of
/// the three places a name has been through.
pub fn tidy(name: &str) -> String {
    let mut name = name.trim().to_lowercase();
    loop {
        let shorter = name
            .trim_end_matches(".git")
            .trim_end_matches('/')
            .trim_end()
            .len();
        if shorter == name.len() {
            return name;
        }
        name.truncate(shorter);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_a_name_has_one_spelling() {
        for (typed, want) in [
            ("team", "team"),
            (" Team ", "team"),
            ("github.com/Owner/Repo.git", "github.com/owner/repo"),
            // The ending in capitals: lower case first, or it would stay.
            ("Repo.GIT", "repo"),
            ("repo.Git", "repo"),
            // More than one, and space before one.
            ("repo.git.git", "repo"),
            ("team .git", "team"),
            ("team.git .GIT ", "team"),
            // A `/` at the end, before an ending or after one.
            ("owner/repo/", "owner/repo"),
            ("owner/repo.git/", "owner/repo"),
            ("owner/repo/.git", "owner/repo"),
            ("owner/repo/ .GIT//", "owner/repo"),
            // Not an ending.
            ("repo.github", "repo.github"),
            ("git", "git"),
            (".github", ".github"),
            ("client-co/*", "client-co/*"),
            ("~", "~"),
            // Nothing is left.
            (".git", ""),
            ("  ", ""),
            ("/", ""),
            ("/.git/", ""),
        ] {
            assert_eq!(tidy(typed), want, "{typed:?}");
        }
    }

    /// The property the three places rely on: a name that has been tidied
    /// once is not changed by being tidied again.
    #[test]
    fn test_tidying_a_tidy_name_changes_nothing() {
        for typed in [
            "X.GIT",
            "x.git.GIT",
            "x .git",
            "x.git .git",
            " x.GIT .Git  ",
            ".git.git",
            "a/b.git/",
            "a/b/.git",
            "a/b.git/.GIT//",
            "a/ /.git",
            "ΌΣ.GIT",
            "İ.GIT",
            "x\u{a0}.git",
            "x.git\t.git\n",
        ] {
            let once = tidy(typed);
            assert_eq!(tidy(&once), once, "{typed:?}");
        }
    }
}
