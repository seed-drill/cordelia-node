//! How Claude Code names the folder it keeps for a directory
//! (`~/.claude/projects/<name>`). The sync adapter finds memory by this
//! name, and the API refuses mappings that would share one.

/// Longest folder name Claude Code uses as it is. It cuts a longer one to
/// this length and adds a hash, which Cordelia does not predict.
pub const FOLDER_NAME_MAX: usize = 200;

/// The name Claude Code gives the folder for a directory: the path with
/// everything that is not an ASCII letter or digit replaced by `-`
/// (`/home/sam/Work` -> `-home-sam-Work`). Claude Code replaces UTF-16
/// units, so a character outside the basic plane becomes two dashes.
///
/// Different directories can share a name: `my-app`, `my.app` and `my/app`
/// all become `my-app`.
pub fn folder_name(path: &str) -> String {
    path.encode_utf16()
        .map(|unit| match u8::try_from(unit) {
            Ok(byte) if byte.is_ascii_alphanumeric() => byte as char,
            _ => '-',
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_folder_names() {
        for (dir, want) in [
            ("/home/sam", "-home-sam"),
            ("/home/sam/Work", "-home-sam-Work"),
            ("/Users/a.b/my_app v2", "-Users-a-b-my-app-v2"),
            ("/home/zoë/café", "-home-zo--caf-"),
            // Outside the basic plane: two UTF-16 units, two dashes.
            ("/home/x/\u{1F4DD}notes", "-home-x---notes"),
        ] {
            assert_eq!(folder_name(dir), want);
        }
        // Three directories, one folder.
        assert_eq!(folder_name("/code/my-app"), folder_name("/code/my.app"));
        assert_eq!(folder_name("/code/my-app"), folder_name("/code/my/app"));
    }
}
