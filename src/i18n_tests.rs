use std::collections::BTreeSet;
use std::process::Command;

use super::*;

fn placeholders(text: &str) -> Vec<&str> {
    let mut names: Vec<_> = text
        .split('{')
        .skip(1)
        .map(|part| part.split_once('}').expect("unclosed placeholder").0)
        .collect();
    names.sort_unstable();
    names
}

#[test]
fn translation_tables_have_identical_keys_and_placeholders() {
    let source = include_str!("i18n.rs");
    let mut expected = None;
    for language in ["zh_cn", "en", "zh_tw"] {
        let table = source
            .split_once(&format!("fn {language}(key: &str)"))
            .unwrap()
            .1
            .split("\nfn ")
            .next()
            .unwrap();
        let keys: BTreeSet<_> = table
            .lines()
            .filter_map(|line| {
                let line = line.trim().strip_prefix('"')?;
                let (key, rest) = line.split_once('"')?;
                rest.trim_start().starts_with("=>").then_some(key)
            })
            .collect();
        assert!(!keys.is_empty(), "translation table unexpectedly empty");
        if let Some(expected) = &expected {
            assert_eq!(&keys, expected, "missing or extra keys in {language}");
        } else {
            expected = Some(keys);
        }
    }
    for key in expected.unwrap() {
        let texts = [zh_cn(key), en(key), zh_tw(key)];
        let source = texts[0].unwrap();
        for text in texts {
            assert!(text.is_some(), "missing translation: {key}");
            let text = text.unwrap();
            assert!(!text.trim().is_empty(), "empty translation: {key}");
            assert_eq!(placeholders(text), placeholders(source), "{key}");
        }
    }
    assert_eq!(zh_cn("unknown-key"), None);
    assert_eq!(en("unknown-key"), None);
    assert_eq!(zh_tw("unknown-key"), None);
}

#[test]
fn language_selection_is_initialized_once_in_each_process() {
    let languages = Lang::all();
    assert_eq!(languages, [Lang::ZhCn, Lang::ZhTw, Lang::En]);
    assert_eq!(
        languages.iter().map(Lang::label).collect::<Vec<_>>(),
        ["简体中文", "繁體中文", "English"]
    );
    for code in ["zh_cn", "zh_tw", "en"] {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "i18n::tests::isolated_language_child",
                "--nocapture",
            ])
            .env("U2SECURE_TEST_LANGUAGE", code)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{code}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn isolated_language_child() {
    let Ok(code) = std::env::var("U2SECURE_TEST_LANGUAGE") else {
        return;
    };
    assert_eq!(current(), Lang::ZhCn);
    let (language, text) = match code.as_str() {
        "en" => (Lang::En, en("cli_welcome")),
        "zh_tw" => (Lang::ZhTw, zh_tw("cli_welcome")),
        "zh_cn" => (Lang::ZhCn, zh_cn("cli_welcome")),
        _ => panic!("unknown language fixture"),
    };
    init(language);
    assert_eq!(current(), language);
    init(if language == Lang::En {
        Lang::ZhCn
    } else {
        Lang::En
    });
    assert_eq!(
        current(),
        language,
        "language must not change after startup"
    );
    assert_eq!(translate("cli_welcome"), text.unwrap());
    assert_eq!(tr("cli_welcome"), text.unwrap());
    assert_eq!(tr("unknown-key"), "unknown-key");
}
