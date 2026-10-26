//! Writes `scripts/netem/<profile>.sh` and `clear.sh` from the simulator
//! profiles. Run from the repository root.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use avianlink_sim::{netem, Profile};

fn main() -> std::io::Result<()> {
    let dir = Path::new("scripts/netem");
    fs::create_dir_all(dir)?;
    let mut files: Vec<(String, String)> = Profile::ALL
        .into_iter()
        .map(|p| (format!("{}.sh", p.name()), netem::script(p)))
        .collect();
    files.push(("clear.sh".to_string(), netem::clear_script().to_string()));
    for (name, body) in files {
        let path = dir.join(&name);
        fs::write(&path, body)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
        println!("wrote {}", path.display());
    }
    Ok(())
}
