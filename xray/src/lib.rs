//! Hidden Text X-Ray: one call that runs both published detectors over the
//! same input and returns everything the page draws, as JSON.
//!
//! - `deobfuscate` (crates.io 1.18.1) undoes encoding tricks step by step and
//!   gives the verdict.
//! - `unicode-interference` (crates.io 1.0.0) labels every character with its
//!   script and marks the look-alike letters.
//!
//! Nothing here adds detection logic of its own. The only extra is
//! [`invisible_name`], which names characters a person can't see so the page
//! can draw them; it does not change the verdict.

use serde::Serialize;
use wasm_bindgen::prelude::*;

/// Longer inputs are cut to this many characters before analysis, so the
/// character strip stays readable and the page stays fast.
pub const MAX_CHARS: usize = 4000;

#[derive(Serialize)]
pub struct Xray {
    /// "clean", "flag" or "block" — deobfuscate's own thresholds.
    pub verdict: &'static str,
    pub score: f32,
    pub flag_threshold: f32,
    pub block_threshold: f32,
    /// The input was longer than [`MAX_CHARS`] and was cut.
    pub truncated: bool,
    /// The cleaned text a model would receive. Empty when `halted`.
    pub normalized: String,
    /// deobfuscate refused to forward the text at all.
    pub halted: bool,
    pub steps: Vec<Step>,
    pub chars: Vec<CharCell>,
    pub lookalikes: Lookalikes,
}

#[derive(Serialize)]
pub struct Step {
    pub kind: String,
    pub original: String,
    pub normalized: String,
    pub detail: String,
    pub confidence: f32,
}

#[derive(Serialize)]
pub struct CharCell {
    pub ch: String,
    pub cp: u32,
    /// Empty for invisible characters.
    pub script: &'static str,
    /// A look-alike inside an otherwise-Latin word: the letter it imitates.
    /// See [`mark_disguised_letters`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imitates: Option<String>,
    /// unicode-interference flagged this position as an intrusion.
    pub intrusion: bool,
    /// Name of an invisible character (zero-width space, hidden tag, ...).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invisible: Option<String>,
}

#[derive(Serialize)]
pub struct Lookalikes {
    pub score: f32,
    pub dominant: &'static str,
    pub count: usize,
    /// Input with every known look-alike swapped for the letter it imitates.
    pub restored: String,
}

/// Names characters that render as nothing. Hidden "tag" characters each
/// shadow one ASCII character; the name shows which, so the page can spell
/// out a hidden message.
pub fn invisible_name(c: char) -> Option<String> {
    let n = c as u32;
    let name = match n {
        0x00AD => "soft hyphen",
        0x200B => "zero-width space",
        0x200C => "zero-width non-joiner",
        0x200D => "zero-width joiner",
        0x200E | 0x200F => "direction mark",
        0x202A..=0x202E => "direction override",
        0x2060 => "word joiner",
        0x2061..=0x2064 => "invisible operator",
        0x2066..=0x2069 => "direction isolate",
        0xFEFF => "zero-width no-break space",
        0xFE00..=0xFE0F | 0xE0100..=0xE01EF => "variation selector",
        0xE0020..=0xE007E => {
            let shadow = char::from_u32(n - 0xE0000).unwrap_or('?');
            return Some(format!("hidden tag '{shadow}'"));
        }
        0xE0000..=0xE007F => "hidden tag",
        _ => return None,
    };
    Some(name.to_string())
}

/// Display rule, not detection: a Cyrillic or Greek look-alike counts as a
/// disguise only inside a word whose other letters are mostly Latin. In real
/// Russian or Greek words the same letters are just letters.
fn mark_disguised_letters(chars: &mut [CharCell]) {
    let mut start = 0;
    while start < chars.len() {
        if chars[start].script.is_empty() || chars[start].script == "Punctuation" {
            start += 1;
            continue;
        }
        let mut end = start;
        while end < chars.len() && !matches!(chars[end].script, "" | "Punctuation") {
            end += 1;
        }
        let word = &mut chars[start..end];
        let latin = word.iter().filter(|c| c.script == "Latin").count();
        if latin * 2 > word.len() {
            for c in word.iter_mut() {
                let ch = c.ch.chars().next().unwrap_or(' ');
                c.imitates = unicode_interference::rotate(ch).map(|(a, _)| a.to_string());
            }
        }
        start = end;
    }
}

pub fn inspect(input: &str) -> Xray {
    let truncated = input.chars().count() > MAX_CHARS;
    let text: String = input.chars().take(MAX_CHARS).collect();

    let result = deobfuscate::analyze(&text);
    let halted = result
        .detections
        .iter()
        .any(|d| d.kind == deobfuscate::PassKind::CjkSuperposition);
    let verdict = if result.should_block() {
        "block"
    } else if result.should_flag() {
        "flag"
    } else {
        "clean"
    };
    let steps = result
        .detections
        .iter()
        .map(|d| Step {
            kind: d.kind.to_string(),
            original: d.original.clone(),
            normalized: d.normalized.clone(),
            detail: d.detail.clone(),
            confidence: d.confidence(),
        })
        .collect();

    // Script labels come from the visible characters only. Invisible ones have
    // no alphabet and are drawn separately; left in, a long hidden run would
    // make "Other" the dominant script and mark every real letter as foreign.
    let all: Vec<char> = text.chars().collect();
    let visible: Vec<usize> = (0..all.len())
        .filter(|&i| invisible_name(all[i]).is_none())
        .collect();
    let report = unicode_interference::probe(&visible.iter().map(|&i| all[i]).collect::<String>());
    let mut chars: Vec<CharCell> = all
        .iter()
        .map(|&c| CharCell {
            ch: c.to_string(),
            cp: c as u32,
            script: "",
            imitates: None,
            intrusion: false,
            invisible: invisible_name(c),
        })
        .collect();
    for (v, &i) in visible.iter().enumerate() {
        chars[i].script = report.scripts[v].name();
    }
    mark_disguised_letters(&mut chars);
    for intr in &report.intrusions {
        if let Some(&i) = visible.get(intr.position) {
            chars[i].intrusion = true;
        }
    }

    Xray {
        verdict,
        score: result.obfuscation_score,
        flag_threshold: result.flag_threshold,
        block_threshold: result.block_threshold,
        truncated,
        normalized: result.normalized,
        halted,
        steps,
        chars,
        lookalikes: Lookalikes {
            score: report.score,
            dominant: report.dominant_script.name(),
            count: report.intrusions.len(),
            restored: report.deobfuscated(),
        },
    }
}

/// Browser entry point: the [`Xray`] for `input`, as a JSON string.
#[wasm_bindgen]
pub fn xray(input: &str) -> String {
    serde_json::to_string(&inspect(input)).unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests;
