//! Small terminal pickers use the system terminal utility, with no new runtime package.
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use envholster_mem::process::ProcessSignals;

use crate::errors::CliError;

pub(crate) fn clean(value: impl AsRef<str>) -> String {
    value
        .as_ref()
        .chars()
        .flat_map(|c| {
            if c.is_control()
                || ('\u{202a}'..='\u{202e}').contains(&c)
                || ('\u{2066}'..='\u{2069}').contains(&c)
            {
                format!("\\u{{{:x}}}", c as u32).chars().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}

fn cancelled() -> CliError {
    CliError::failure("Setup cancelled. Run envholster setup to continue.", None)
}

pub(crate) fn line(prompt: &str) -> Result<String, CliError> {
    crate::context::prompt_line(prompt, "envholster setup")
}

pub(crate) fn confirm(prompt: &str, yes_default: bool) -> Result<bool, CliError> {
    let suffix = if yes_default { "[Y/n]" } else { "[y/N]" };
    loop {
        let answer = line(&format!("{prompt} {suffix}: "))?;
        match answer.to_ascii_lowercase().as_str() {
            "" => return Ok(yes_default),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => eprintln!("Enter yes or no."),
        }
    }
}

struct Terminal {
    input: File,
    state: String,
    stty: PathBuf,
    signals: ProcessSignals,
}

impl Terminal {
    fn open(plain: bool) -> Option<Self> {
        if plain
            || !std::io::stdin().is_terminal()
            || !std::io::stderr().is_terminal()
            || std::env::var("TERM").is_ok_and(|s| s == "dumb")
        {
            return None;
        }
        let input = File::options()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .ok()?;
        let stty = crate::setup::program("stty")?;
        let state = Command::new(&stty)
            .arg("-g")
            .stdin(input.try_clone().ok()?)
            .output()
            .ok()?;
        if !state.status.success() {
            return None;
        }
        let state = String::from_utf8(state.stdout).ok()?.trim().to_owned();
        let signals = ProcessSignals::install().ok()?;
        let mut terminal = Self {
            input,
            state,
            stty,
            signals,
        };
        if !terminal
            .command(&["-icanon", "-echo", "-isig", "min", "0", "time", "1"])
            .ok()?
        {
            return None;
        }
        eprint!("\x1b[?1049h\x1b[?25l");
        let _ = std::io::stderr().flush();
        Some(terminal)
    }

    fn command(&mut self, args: &[&str]) -> std::io::Result<bool> {
        Ok(Command::new(&self.stty)
            .args(args)
            .stdin(self.input.try_clone()?)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?
            .success())
    }

    fn key(&mut self) -> Result<Vec<u8>, CliError> {
        loop {
            if !self.signals.take_pending().is_empty() {
                return Err(cancelled());
            }
            let mut byte = [0u8; 1];
            if self.input.read(&mut byte)? == 0 {
                continue;
            }
            if matches!(byte[0], 3 | 4) {
                return Err(cancelled());
            }
            let mut result = vec![byte[0]];
            if byte[0] == 27 {
                for _ in 0..2 {
                    if self.input.read(&mut byte)? == 0 {
                        break;
                    }
                    result.push(byte[0]);
                }
            }
            return Ok(result);
        }
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        let state = self.state.clone();
        let _ = self.command(&[&state]);
        eprint!("\x1b[?25h\x1b[?1049l");
        let _ = std::io::stderr().flush();
    }
}

pub(crate) fn select(
    title: &str,
    items: &[String],
    multiple: bool,
    defaults: &[usize],
    plain: bool,
) -> Result<Vec<usize>, CliError> {
    if items.is_empty() {
        return Ok(vec![]);
    }
    let Some(mut terminal) = Terminal::open(plain) else {
        return select_plain(title, items, multiple, defaults);
    };
    let mut chosen: BTreeSet<usize> = defaults.iter().copied().collect();
    let mut position = defaults.first().copied().unwrap_or(0).min(items.len() - 1);
    let mut query = String::new();
    let mut searching = false;
    loop {
        let visible: Vec<usize> = items
            .iter()
            .enumerate()
            .filter_map(|(i, item)| {
                item.to_lowercase()
                    .contains(&query.to_lowercase())
                    .then_some(i)
            })
            .collect();
        if !visible.contains(&position) {
            position = visible.first().copied().unwrap_or(0);
        }
        eprint!("\x1b[H\x1b[2J\n  ENVHOLSTER\n\n  {}\n\n", clean(title));
        if multiple {
            eprintln!("  ↑/↓ move   Space select   A select visible   N clear visible");
        } else {
            eprintln!("  ↑/↓ move");
        }
        eprintln!(
            "  / search   Enter {}   Esc cancel\n",
            if multiple { "continue" } else { "choose" }
        );
        if !query.is_empty() || searching {
            eprintln!(
                "  Search: {}{}\n",
                clean(&query),
                if searching { "_" } else { "" }
            );
        }
        let current = visible.iter().position(|i| *i == position).unwrap_or(0);
        let start = current.saturating_sub(8);
        for i in visible.iter().skip(start).take(16) {
            let mark = if multiple {
                if chosen.contains(i) {
                    "[x] "
                } else {
                    "[ ] "
                }
            } else {
                ""
            };
            let arrow = if *i == position { ">" } else { " " };
            eprintln!("  {arrow} {mark}{}", clean(&items[*i]));
        }
        eprintln!("\n  {} shown · {} selected", visible.len(), chosen.len());
        std::io::stderr().flush()?;
        let key = terminal.key()?;
        if searching {
            match key.as_slice() {
                b"\r" | b"\n" | b"\x1b" => searching = false,
                [127] | [8] => {
                    query.pop();
                }
                [c] if c.is_ascii_graphic() || *c == b' ' => query.push(*c as char),
                _ => {}
            }
            continue;
        }
        match key.as_slice() {
            b"\x1b[A" | b"k" => {
                if current > 0 {
                    position = visible[current - 1];
                }
            }
            b"\x1b[B" | b"j" => {
                if current + 1 < visible.len() {
                    position = visible[current + 1];
                }
            }
            b" " if multiple && !visible.is_empty() => {
                if !chosen.insert(position) {
                    chosen.remove(&position);
                }
            }
            b"a" | b"A" if multiple => chosen.extend(visible.iter()),
            b"n" | b"N" if multiple => chosen.retain(|i| !visible.contains(i)),
            b"/" => searching = true,
            b"\x1b" | b"q" => return Err(cancelled()),
            b"\r" | b"\n" => {
                if multiple {
                    return Ok(chosen.into_iter().collect());
                }
                if !multiple && !visible.is_empty() {
                    return Ok(vec![position]);
                }
            }
            _ => {}
        }
    }
}

fn select_plain(
    title: &str,
    items: &[String],
    multiple: bool,
    defaults: &[usize],
) -> Result<Vec<usize>, CliError> {
    eprintln!("\n{}", clean(title));
    for (i, item) in items.iter().enumerate() {
        eprintln!("  {}. {}", i + 1, clean(item));
    }
    loop {
        let answer = line(if multiple {
            "Choose numbers or ranges (1,3-5), all, or q to cancel: "
        } else {
            "Choose a number, or q to cancel: "
        })?;
        if answer.eq_ignore_ascii_case("q") {
            return Err(cancelled());
        }
        if answer.is_empty() && !defaults.is_empty() {
            return Ok(defaults.to_vec());
        }
        if let Some(indices) = parse_selection(&answer, items.len(), multiple) {
            return Ok(indices);
        }
        eprintln!(
            "Choose {} from the numbered list.",
            if multiple {
                "one or more projects"
            } else {
                "one item"
            }
        );
    }
}

fn parse_selection(answer: &str, count: usize, multiple: bool) -> Option<Vec<usize>> {
    if multiple && answer.eq_ignore_ascii_case("all") {
        return Some((0..count).collect());
    }
    let mut chosen = BTreeSet::new();
    for part in answer.split([',', ' ']).filter(|s| !s.is_empty()) {
        let (start, end) = part.split_once('-').unwrap_or((part, part));
        let start = start.parse::<usize>().ok()?;
        let end = end.parse::<usize>().ok()?;
        if start == 0 || end < start || end > count {
            return None;
        }
        chosen.extend((start - 1)..end);
    }
    (!chosen.is_empty() && (multiple || chosen.len() == 1)).then(|| chosen.into_iter().collect())
}

pub(crate) fn resolve_path(path: &Path, base: &Path) -> PathBuf {
    if let Ok(rest) = path.strip_prefix("~") {
        return std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| base.to_owned())
            .join(rest);
    }
    if path.is_absolute() {
        path.to_owned()
    } else {
        base.join(path)
    }
}

pub(crate) fn resolve_input_path(input: &str, base: &Path) -> PathBuf {
    let input = input.trim();
    let literal = resolve_path(Path::new(input), base);
    if literal.is_dir() || !input.starts_with(['\'', '"']) && !input.contains('\\') {
        return literal;
    }
    // Folder dragging uses shell quoting, but pasted paths must never execute
    // substitutions. CLI path arguments already passed through the user's shell.
    let mut decoded = String::new();
    let mut quoted = None;
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        match (quoted, c) {
            (Some('\''), '\'') | (Some('"'), '"') => quoted = None,
            (Some('\''), _) => decoded.push(c),
            (None, '\'' | '"') => quoted = Some(c),
            (_, '\\') => {
                if let Some(&next) = chars.peek() {
                    if quoted.is_none() || matches!(next, '$' | '`' | '"' | '\\') {
                        decoded.push(next);
                        chars.next();
                    } else {
                        decoded.push(c);
                    }
                } else {
                    decoded.push(c);
                }
            }
            _ => decoded.push(c),
        }
    }
    if quoted.is_some() {
        literal
    } else {
        resolve_path(Path::new(&decoded), base)
    }
}

pub(crate) fn folder(title: &str, initial: &Path, plain: bool) -> Result<PathBuf, CliError> {
    let mut current = std::fs::canonicalize(initial)?;
    loop {
        let mut children: Vec<PathBuf> = std::fs::read_dir(&current)?
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
            .map(|e| e.path())
            .collect();
        children.sort();
        let mut items = vec![
            "Use this folder".into(),
            "Go to parent folder".into(),
            "Paste or type a folder path".into(),
        ];
        items.extend(
            children
                .iter()
                .map(|p| format!("{}/", p.file_name().unwrap_or_default().to_string_lossy())),
        );
        let picked = select(
            &format!("{title} · {}", clean(current.to_string_lossy())),
            &items,
            false,
            &[0],
            plain,
        )?[0];
        match picked {
            0 => return Ok(current),
            1 => {
                if let Some(parent) = current.parent() {
                    current = parent.to_owned();
                }
            }
            2 => loop {
                let entered = line("Paste a folder path, or drag a folder here: ")?;
                if entered.is_empty() {
                    break;
                }
                match std::fs::canonicalize(resolve_input_path(&entered, &current)) {
                    Ok(path) if path.is_dir() => {
                        current = path;
                        break;
                    }
                    _ => eprintln!(
                        "That folder could not be opened. Try another path, or press Enter to return to the folder picker."
                    ),
                }
            },
            i => current = children[i - 3].clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ranges_validate_before_selection() {
        assert_eq!(parse_selection("1,3-5", 5, true), Some(vec![0, 2, 3, 4]));
        for input in ["0", "2-1", "1-99999999", "6", "", "1,x"] {
            assert!(parse_selection(input, 5, true).is_none());
        }
        assert!(parse_selection("1,2", 5, false).is_none());
    }
    #[test]
    fn terminal_labels_cannot_inject_control_sequences() {
        assert!(!clean("folder\x1b[2J\n\u{202e}").contains('\x1b'));
        assert!(!clean("folder\n").contains('\n'));
    }

    #[test]
    fn pasted_paths_decode_dragging_and_quotes_without_shell_expansion() {
        let base = Path::new("/projects");
        for input in [
            r"Developer\'s\ Projects\ \(QA\)",
            r#""Developer's Projects (QA)""#,
            r#"'Developer'\''s Projects (QA)'"#,
            "Developer's Projects (QA)",
        ] {
            assert_eq!(
                resolve_input_path(input, base),
                base.join("Developer's Projects (QA)")
            );
        }
        assert_eq!(
            resolve_input_path(r#""$(touch sentinel) `$USER`""#, base),
            base.join("$(touch sentinel) `$USER`")
        );
        assert_eq!(
            resolve_input_path(r#""folder\name""#, base),
            base.join(r"folder\name")
        );
    }

    #[test]
    fn cli_paths_keep_literal_quotes_backslashes_and_whitespace() {
        let base = Path::new("/projects");
        for input in ["'literal'", r"literal\ folder", " spaced "] {
            assert_eq!(resolve_path(Path::new(input), base), base.join(input));
        }
    }
}
