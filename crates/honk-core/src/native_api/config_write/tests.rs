use std::fs;
use std::os::unix::fs::symlink;

use super::*;

const ORIGINAL: &str = "# Keep this source comment: π\nrouting {\n    fallback: direct\n}\n";
const REPLACEMENT: &str =
    "# Edited comment, unchanged policy: λ\r\nrouting {\r\n    fallback: direct\r\n}\r\n";
const LIMIT: usize = 4096;

fn fixture() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.dae");
    fs::write(&path, ORIGINAL).unwrap();
    fs::set_permissions(&path, Permissions::from_mode(0o640)).unwrap();
    (directory, path)
}

fn assert_only_config(directory: &Path) {
    let names: Vec<_> = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(names, [OsString::from("config.dae")]);
}

#[test]
fn replacement_preserves_exact_bytes_mode_and_old_open_inode() {
    let (directory, path) = fixture();
    let mut old_file = File::open(&path).unwrap();
    let old_metadata = old_file.metadata().unwrap();
    let source = SourceFile::open(&path, LIMIT).unwrap();
    let hash = source.sha256();
    source
        .replace(&hash, REPLACEMENT, || {
            assert_eq!(fs::read(&path).unwrap(), ORIGINAL.as_bytes());
            Ok(())
        })
        .unwrap();

    assert_eq!(fs::read(&path).unwrap(), REPLACEMENT.as_bytes());
    let mut retained = String::new();
    old_file.read_to_string(&mut retained).unwrap();
    assert_eq!(retained, ORIGINAL);
    assert_ne!(fs::metadata(&path).unwrap().ino(), old_metadata.ino());
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o640);
    assert_eq!(old_file.metadata().unwrap().mode() & 0o7777, 0o640);
    let replaced = SourceFile::open(&path, LIMIT).unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), REPLACEMENT);
    assert_eq!(
        replaced.sha256(),
        crate::native_api::config::digest(REPLACEMENT.as_bytes())
    );
    assert_only_config(directory.path());
}

#[test]
fn conflicting_disk_edits_never_overwrite_the_editor() {
    for rename in [false, true] {
        let (directory, path) = fixture();
        let source = SourceFile::open(&path, LIMIT).unwrap();
        let hash = source.sha256();
        let editor_content = if rename {
            ORIGINAL
        } else {
            "# editor changed the open inode\n"
        };
        if rename {
            let replacement = directory.path().join("editor.dae");
            fs::write(&replacement, editor_content).unwrap();
            fs::set_permissions(&replacement, Permissions::from_mode(0o640)).unwrap();
            fs::rename(replacement, &path).unwrap();
        } else {
            fs::write(&path, editor_content).unwrap();
        }
        assert_eq!(
            source.replace(&hash, REPLACEMENT, || panic!(
                "changed target reached admission"
            )),
            Err(WriteError::Conflict)
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), editor_content);
        assert_only_config(directory.path());
    }
}

#[test]
fn wrong_precondition_and_dependency_rejection_leave_disk_unchanged() {
    let (directory, path) = fixture();
    let source = SourceFile::open(&path, LIMIT).unwrap();
    assert_eq!(
        source.replace(&"0".repeat(64), REPLACEMENT, || panic!(
            "wrong hash reached admission"
        )),
        Err(WriteError::Conflict)
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), ORIGINAL);
    assert_only_config(directory.path());

    let source = SourceFile::open(&path, LIMIT).unwrap();
    let hash = source.sha256();
    assert_eq!(
        source.replace(&hash, REPLACEMENT, || Err(WriteError::Conflict)),
        Err(WriteError::Conflict)
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), ORIGINAL);
    assert_only_config(directory.path());
}

#[test]
fn target_edit_during_dependency_admission_is_preserved() {
    let (directory, path) = fixture();
    let source = SourceFile::open(&path, LIMIT).unwrap();
    let hash = source.sha256();
    let external = "# edited while dependencies were being validated\n";
    assert_eq!(
        source.replace(&hash, REPLACEMENT, || {
            fs::write(&path, external).unwrap();
            Ok(())
        }),
        Err(WriteError::Conflict)
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), external);
    assert_only_config(directory.path());
}

#[test]
fn target_symlinks_are_never_read_or_replaced() {
    let (directory, path) = fixture();
    let source = SourceFile::open(&path, LIMIT).unwrap();
    let hash = source.sha256();
    let outside = tempfile::tempdir().unwrap();
    let private = outside.path().join("private.dae");
    fs::write(&private, "private content").unwrap();
    fs::remove_file(&path).unwrap();
    symlink(&private, &path).unwrap();

    assert!(matches!(
        SourceFile::open(&path, LIMIT),
        Err(WriteError::UnsafePath)
    ));
    assert_eq!(
        source.replace(&hash, REPLACEMENT, || panic!("symlink reached admission")),
        Err(WriteError::UnsafePath)
    );
    assert!(
        fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read_to_string(private).unwrap(), "private content");
    assert_only_config(directory.path());
}

#[test]
fn moved_parent_cannot_redirect_writes_or_leave_temporary_files() {
    for replace_with_symlink in [false, true] {
        let outer = tempfile::tempdir().unwrap();
        let parent = outer.path().join("parent");
        let retained = outer.path().join("retained");
        let outside = outer.path().join("outside");
        fs::create_dir(&parent).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(parent.join("config.dae"), ORIGINAL).unwrap();
        fs::write(outside.join("config.dae"), "outside").unwrap();
        let source = SourceFile::open(&parent.join("config.dae"), LIMIT).unwrap();
        let hash = source.sha256();
        fs::rename(&parent, &retained).unwrap();
        if replace_with_symlink {
            symlink(&outside, &parent).unwrap();
        } else {
            fs::create_dir(&parent).unwrap();
            fs::write(parent.join("config.dae"), "new parent").unwrap();
        }

        assert_eq!(
            source.replace(&hash, REPLACEMENT, || panic!(
                "changed parent reached admission"
            )),
            Err(if replace_with_symlink {
                WriteError::UnsafePath
            } else {
                WriteError::Conflict
            })
        );
        assert_eq!(
            fs::read_to_string(retained.join("config.dae")).unwrap(),
            ORIGINAL
        );
        assert_eq!(
            fs::read_to_string(outside.join("config.dae")).unwrap(),
            "outside"
        );
        assert_only_config(&retained);
        if !replace_with_symlink {
            assert_eq!(
                fs::read_to_string(parent.join("config.dae")).unwrap(),
                "new parent"
            );
            assert_only_config(&parent);
        }
    }
}

#[test]
fn ancestor_symlinks_are_rejected() {
    let (directory, path) = fixture();
    let outer = tempfile::tempdir().unwrap();
    let link = outer.path().join("link");
    symlink(directory.path(), &link).unwrap();
    fs::create_dir(directory.path().join("nested")).unwrap();
    fs::write(directory.path().join("nested/config.dae"), ORIGINAL).unwrap();
    assert!(matches!(
        SourceFile::open(&link.join("nested/config.dae"), LIMIT),
        Err(WriteError::UnsafePath)
    ));
    assert_eq!(fs::read_to_string(path).unwrap(), ORIGINAL);
}

#[test]
fn reads_and_replacements_enforce_byte_limit_and_regular_utf8_files() {
    let (directory, path) = fixture();
    assert!(matches!(
        SourceFile::open(&path, ORIGINAL.len() - 1),
        Err(WriteError::TooLarge)
    ));
    let source = SourceFile::open(&path, ORIGINAL.len()).unwrap();
    let hash = source.sha256();
    assert_eq!(
        source.replace(&hash, REPLACEMENT, || panic!(
            "oversized write reached admission"
        )),
        Err(WriteError::TooLarge)
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), ORIGINAL);
    assert_only_config(directory.path());

    fs::write(&path, [0xff, 0xfe]).unwrap();
    assert!(matches!(
        SourceFile::open(&path, LIMIT),
        Err(WriteError::InvalidUtf8)
    ));
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    assert!(matches!(
        SourceFile::open(&path, LIMIT),
        Err(WriteError::UnsafePath)
    ));
    fs::remove_dir(&path).unwrap();
    nix::unistd::mkfifo(&path, Mode::from_bits_truncate(0o600)).unwrap();
    assert!(matches!(
        SourceFile::open(&path, LIMIT),
        Err(WriteError::UnsafePath)
    ));
}

#[test]
fn file_sync_failure_is_invisible_but_directory_sync_failure_keeps_new_bytes() {
    for fault in [SyncFault::File, SyncFault::Directory] {
        let (directory, path) = fixture();
        let old_inode = fs::metadata(&path).unwrap().ino();
        let mut source = SourceFile::open(&path, LIMIT).unwrap();
        let hash = source.sha256();
        source.sync_fault = Some(fault);
        let mut admitted = false;
        let result = source.replace(&hash, REPLACEMENT, || {
            admitted = true;
            assert_eq!(fs::read_to_string(&path).unwrap(), ORIGINAL);
            Ok(())
        });
        if fault == SyncFault::File {
            assert_eq!(result, Err(WriteError::Unavailable));
            assert!(!admitted);
            assert_eq!(fs::read_to_string(&path).unwrap(), ORIGINAL);
            assert_eq!(fs::metadata(&path).unwrap().ino(), old_inode);
        } else {
            assert_eq!(result, Err(WriteError::ChangedButNotDurable));
            assert!(admitted);
            assert_eq!(fs::read_to_string(&path).unwrap(), REPLACEMENT);
            assert_ne!(fs::metadata(&path).unwrap().ino(), old_inode);
        }
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o640);
        assert_only_config(directory.path());
    }
}
